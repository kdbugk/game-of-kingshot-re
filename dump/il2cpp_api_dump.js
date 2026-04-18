'use strict';
/**
 * il2cpp_api_dump.js
 *
 * Enumera tipos, métodos e campos do IL2CPP usando as APIs de runtime
 * exportadas por libil2cpp.so — funciona independente do formato do metadata
 * (HTPX, padrão, etc.) porque acessa as estruturas já construídas em memória.
 *
 * Roda APÓS il2cpp_init completar. Envia os dados como JSON via send().
 */

let dumpDone = false;

// ── Utilitários ──────────────────────────────────────────────────────────────

function strToArrayBuffer(str) {
  // UTF-8 encoder manual (TextEncoder não existe no runtime Frida)
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x80) {
      bytes.push(c);
    } else if (c < 0x800) {
      bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c < 0xd800 || c >= 0xe000) {
      bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      // surrogate pair
      i++;
      const c2 = str.charCodeAt(i);
      const cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
      bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f),
                 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
  }
  const buf = new ArrayBuffer(bytes.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) view[i] = bytes[i];
  return buf;
}

function readStr(ptr) {
  if (!ptr || ptr.isNull()) return '';
  try { return ptr.readUtf8String(); } catch (_) { return '(?)'; }
}

function sizeStr(b) {
  return b >= 1048576 ? (b/1048576).toFixed(2)+'MB' : (b/1024).toFixed(1)+'KB';
}

// ── API wrappers ─────────────────────────────────────────────────────────────

function initApi(mod) {
  function fn(name, ret, args) {
    try {
      const addr = mod.getExportByName(name);
      return new NativeFunction(addr, ret, args);
    } catch (_) {
      return null;
    }
  }

  return {
    domain_get:               fn('il2cpp_domain_get',                    'pointer', []),
    domain_get_assemblies:    fn('il2cpp_domain_get_assemblies',         'pointer', ['pointer','pointer']),
    assembly_get_image:       fn('il2cpp_assembly_get_image',            'pointer', ['pointer']),
    image_get_name:           fn('il2cpp_image_get_name',                'pointer', ['pointer']),
    image_get_filename:       fn('il2cpp_image_get_filename',            'pointer', ['pointer']),
    image_get_class_count:    fn('il2cpp_image_get_class_count',         'uint32',  ['pointer']),
    image_get_class:          fn('il2cpp_image_get_class',               'pointer', ['pointer','uint32']),
    class_get_name:           fn('il2cpp_class_get_name',                'pointer', ['pointer']),
    class_get_namespace:      fn('il2cpp_class_get_namespace',           'pointer', ['pointer']),
    class_get_parent:         fn('il2cpp_class_get_parent',              'pointer', ['pointer']),
    class_get_flags:          fn('il2cpp_class_get_flags',               'int32',   ['pointer']),
    class_get_methods:        fn('il2cpp_class_get_methods',             'pointer', ['pointer','pointer']),
    class_get_fields:         fn('il2cpp_class_get_fields',              'pointer', ['pointer','pointer']),
    class_get_properties:     fn('il2cpp_class_get_properties',          'pointer', ['pointer','pointer']),
    class_get_interfaces:     fn('il2cpp_class_get_interfaces',          'pointer', ['pointer','pointer']),
    class_get_nested_types:   fn('il2cpp_class_get_nested_types',        'pointer', ['pointer','pointer']),
    method_get_name:          fn('il2cpp_method_get_name',               'pointer', ['pointer']),
    method_get_return_type:   fn('il2cpp_method_get_return_type',        'pointer', ['pointer']),
    method_get_param_count:   fn('il2cpp_method_get_param_count',        'uint32',  ['pointer']),
    method_get_param:         fn('il2cpp_method_get_param',              'pointer', ['pointer','uint32']),
    method_get_param_name:    fn('il2cpp_method_get_param_name',         'pointer', ['pointer','uint32']),
    method_is_static:         fn('il2cpp_method_is_static',              'bool',    ['pointer']),
    method_is_generic:        fn('il2cpp_method_is_generic',             'bool',    ['pointer']),
    method_get_flags:         fn('il2cpp_method_get_flags',              'uint32',  ['pointer','pointer']),
    field_get_name:           fn('il2cpp_field_get_name',                'pointer', ['pointer']),
    field_get_type:           fn('il2cpp_field_get_type',                'pointer', ['pointer']),
    field_get_flags:          fn('il2cpp_field_get_flags',               'int32',   ['pointer']),
    field_get_offset:         fn('il2cpp_field_get_offset',              'int32',   ['pointer']),
    field_static_get_value:   fn('il2cpp_field_static_get_value',        'void',    ['pointer','pointer']),
    type_get_name:            fn('il2cpp_type_get_name',                 'pointer', ['pointer']),
    type_get_type:            fn('il2cpp_type_get_type',                 'int32',   ['pointer']),
    property_get_name:        fn('il2cpp_property_get_name',             'pointer', ['pointer']),
    property_get_get_method:  fn('il2cpp_property_get_get_method',       'pointer', ['pointer']),
    property_get_set_method:  fn('il2cpp_property_get_set_method',       'pointer', ['pointer']),
    class_get_method_from_name: fn('il2cpp_class_get_method_from_name',  'pointer', ['pointer','pointer','int32']),
    runtime_invoke:           fn('il2cpp_runtime_invoke',                'pointer', ['pointer','pointer','pointer','pointer']),
  };
}

// ── Dump de um método ────────────────────────────────────────────────────────

function dumpMethod(api, meth, il2cppBase) {
  if (!meth || meth.isNull()) return null;
  const name = readStr(api.method_get_name ? api.method_get_name(meth) : null);
  if (!name) return null;

  const obj = { name };

  // Endereço da função (ponteiro no MethodInfo)
  try {
    const fnPtr = meth.readPointer();
    if (!fnPtr.isNull()) {
      obj.rva = '0x' + fnPtr.sub(il2cppBase).toString(16);
      obj.addr = fnPtr.toString();
    }
  } catch (_) {}

  // Flags / static
  if (api.method_is_static) {
    try { obj.is_static = api.method_is_static(meth); } catch (_) {}
  }

  // Tipo de retorno
  if (api.method_get_return_type && api.type_get_name) {
    try {
      const rt = api.method_get_return_type(meth);
      if (rt && !rt.isNull()) obj.ret = readStr(api.type_get_name(rt));
    } catch (_) {}
  }

  // Parâmetros
  if (api.method_get_param_count && api.method_get_param_name && api.type_get_name) {
    try {
      const nparams = api.method_get_param_count(meth);
      const params = [];
      for (let i = 0; i < nparams && i < 32; i++) {
        const pt = api.method_get_param ? api.method_get_param(meth, i) : null;
        const pname = api.method_get_param_name(meth, i);
        params.push({
          name: readStr(pname),
          type: (pt && !pt.isNull() && api.type_get_name) ? readStr(api.type_get_name(pt)) : '?'
        });
      }
      obj.params = params;
    } catch (_) {}
  }

  return obj;
}

// ── Dump de uma classe ───────────────────────────────────────────────────────

function dumpClass(api, klass, il2cppBase) {
  if (!klass || klass.isNull()) return null;

  const name = readStr(api.class_get_name(klass));
  const ns   = readStr(api.class_get_namespace(klass));
  if (!name) return null;

  const obj = {
    name,
    namespace:  ns || '',
    fullName:   ns ? ns + '.' + name : name,
    addr:       klass.toString(),
    methods:    [],
    fields:     [],
    properties: [],
  };

  // Flags
  if (api.class_get_flags) {
    try { obj.flags = '0x' + api.class_get_flags(klass).toString(16); } catch (_) {}
  }

  // Parent
  if (api.class_get_parent) {
    try {
      const par = api.class_get_parent(klass);
      if (par && !par.isNull()) {
        obj.parent = readStr(api.class_get_name(par));
      }
    } catch (_) {}
  }

  // Métodos
  if (api.class_get_methods) {
    try {
      let iter = Memory.alloc(Process.pointerSize);
      iter.writePointer(NULL);
      let meth;
      let mcount = 0;
      while ((meth = api.class_get_methods(klass, iter)) && !meth.isNull() && mcount < 512) {
        const md = dumpMethod(api, meth, il2cppBase);
        if (md) obj.methods.push(md);
        mcount++;
      }
    } catch (_) {}
  }

  // Campos
  if (api.class_get_fields && api.field_get_name && api.field_get_type && api.type_get_name) {
    try {
      let iter = Memory.alloc(Process.pointerSize);
      iter.writePointer(NULL);
      let field;
      let fcount = 0;
      while ((field = api.class_get_fields(klass, iter)) && !field.isNull() && fcount < 256) {
        const fname = readStr(api.field_get_name(field));
        if (fname) {
          const fobj = { name: fname };
          try {
            const ft = api.field_get_type(field);
            if (ft && !ft.isNull()) fobj.type = readStr(api.type_get_name(ft));
          } catch (_) {}
          if (api.field_get_flags) {
            try { fobj.flags = '0x' + api.field_get_flags(field).toString(16); } catch (_) {}
          }
          if (api.field_get_offset) {
            try {
              const off = api.field_get_offset(field);
              // offset -1 = campo estático (sem offset de instância)
              if (off >= 0) fobj.offset = '0x' + off.toString(16);
              else          fobj.offset = 'static';
            } catch (_) {}
          }
          obj.fields.push(fobj);
        }
        fcount++;
      }
    } catch (_) {}
  }

  // Properties
  if (api.class_get_properties && api.property_get_name) {
    try {
      let iter = Memory.alloc(Process.pointerSize);
      iter.writePointer(NULL);
      let prop;
      let pcount = 0;
      while ((prop = api.class_get_properties(klass, iter)) && !prop.isNull() && pcount < 128) {
        const pname = readStr(api.property_get_name(prop));
        if (pname) obj.properties.push({ name: pname });
        pcount++;
      }
    } catch (_) {}
  }

  return obj;
}

// ── Dump principal ───────────────────────────────────────────────────────────

function runDump() {
  if (dumpDone) return;
  dumpDone = true;

  console.log('\n[IL2CPP-API] Iniciando dump via runtime APIs...');

  const mod = Process.getModuleByName('libil2cpp.so');
  const il2cppBase = mod.base;
  console.log('[IL2CPP-API] base=' + il2cppBase + '  size=' + sizeStr(mod.size));

  const api = initApi(mod);

  // Verificar quais APIs estão disponíveis
  const available = Object.entries(api)
    .filter(([, v]) => v !== null)
    .map(([k]) => k);
  console.log('[IL2CPP-API] APIs disponíveis: ' + available.length);

  // Obter domínio
  if (!api.domain_get) {
    console.log('[IL2CPP-API] il2cpp_domain_get não encontrado!');
    return;
  }
  const domain = api.domain_get();
  if (!domain || domain.isNull()) {
    console.log('[IL2CPP-API] domain é null!');
    return;
  }
  console.log('[IL2CPP-API] domain=' + domain);

  // Obter assemblies
  if (!api.domain_get_assemblies) {
    console.log('[IL2CPP-API] il2cpp_domain_get_assemblies não encontrado!');
    return;
  }
  const sizePtr = Memory.alloc(4);
  const assembliesPtr = api.domain_get_assemblies(domain, sizePtr);
  const nAssemblies = sizePtr.readU32();
  console.log('[IL2CPP-API] assemblies: ' + nAssemblies);

  if (nAssemblies === 0 || assembliesPtr.isNull()) {
    console.log('[IL2CPP-API] Nenhum assembly encontrado!');
    return;
  }

  const result = { assemblies: [] };
  let totalClasses = 0;
  let totalMethods = 0;

  for (let ai = 0; ai < nAssemblies; ai++) {
    const assembly = assembliesPtr.add(ai * Process.pointerSize).readPointer();
    if (!assembly || assembly.isNull()) continue;

    const image = api.assembly_get_image ? api.assembly_get_image(assembly) : null;
    if (!image || image.isNull()) continue;

    const imgName = api.image_get_name ? readStr(api.image_get_name(image)) : '(?)';
    const classCount = api.image_get_class_count ? api.image_get_class_count(image) : 0;

    console.log('[IL2CPP-API] [' + ai + '] ' + imgName + '  classes=' + classCount);

    const assemblyObj = { name: imgName, classes: [] };

    // Limitar assemblies grandes para não travar (Assembly-CSharp pode ter 10k+ classes)
    const limit = imgName.includes('Assembly-CSharp') ? 9999 : 2000;

    for (let ci = 0; ci < Math.min(classCount, limit); ci++) {
      const klass = api.image_get_class ? api.image_get_class(image, ci) : null;
      if (!klass || klass.isNull()) continue;

      const cd = dumpClass(api, klass, il2cppBase);
      if (cd) {
        assemblyObj.classes.push(cd);
        totalClasses++;
        totalMethods += cd.methods.length;
      }
    }

    result.assemblies.push(assemblyObj);

    // Enviar assembly como chunk separado para não acumular memória
    send({ type: 'assembly', index: ai, name: imgName, class_count: assemblyObj.classes.length },
         strToArrayBuffer(JSON.stringify(assemblyObj)));
  }

  console.log('\n[IL2CPP-API] Dump completo!');
  console.log('  Assemblies: ' + result.assemblies.length);
  console.log('  Classes:    ' + totalClasses);
  console.log('  Métodos:    ' + totalMethods);
  send({ type: 'dump_complete', assemblies: result.assemblies.length, classes: totalClasses, methods: totalMethods });
}

// ── Main: aguarda il2cpp_init ─────────────────────────────────────────────────

function main() {
  console.log('[+] il2cpp_api_dump.js — aguardando libil2cpp.so...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (!mod) return;
    clearInterval(poll);
    console.log('[+] libil2cpp.so: base=' + mod.base);

    try {
      const initFn = mod.getExportByName('il2cpp_init');
      Interceptor.attach(initFn, {
        onLeave() {
          console.log('[il2cpp_init] LEAVE — iniciando dump em 500ms');
          setTimeout(runDump, 500);
        }
      });
      console.log('[+] il2cpp_init hookado');
    } catch (e) {
      console.log('[!] il2cpp_init: ' + e.message);
      // Tentar rodar direto se il2cpp já inicializou
      setTimeout(runDump, 2000);
    }
  }, 100);
}

main();
