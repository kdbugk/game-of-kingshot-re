import unittest, server_rules as R

class T(unittest.TestCase):
    def test_errcodes_loaded(self):
        self.assertGreater(len(R.ERR), 3000)
        self.assertEqual(R.code("err_climbtower_level_already_passed"), 16807)
        self.assertEqual(R.code("err_param_illegal"), 2)
        for k in set(R.REPLAY_ERR.values()): self.assertIn(k, R.ERR)
    def test_climbtower_40021_twice(self):
        r = R.ReplayRegistry()
        self.assertIsNone(r.check_and_mark("climbtower_level", 40021))
        self.assertEqual(r.check_and_mark("climbtower_level", 40021), 16807)
        self.assertIsNone(r.check("climbtower_level", 40022))
    def test_mail_and_daily(self):
        r = R.ReplayRegistry()
        self.assertIsNone(r.check("mail_attach", 7)); r.mark_done("mail_attach", 7)
        self.assertEqual(r.check("mail_attach", 7), 1202)
        r.mark_done("daily_task_reward", 1); self.assertEqual(r.check("daily_task_reward", 1), 10522)
        r.reset_daily(); self.assertIsNone(r.check("daily_task_reward", 1))
        self.assertEqual(r.check("mail_attach", 7), 1202)
    def test_shop_info_before_loaddata(self):
        s = R.Session()
        self.assertEqual(s.check("req_shop_info"), 2)
        self.assertIsNone(s.check("req_heartbeat")); self.assertIsNone(s.check(22))
        self.assertEqual(s.check("req_loaddata"), 2)    # sem login
        s.login_ok(); self.assertEqual(s.check("req_shop_info"), 2)
        self.assertIsNone(s.check("req_loaddata")); self.assertIsNone(s.check("req_shop_info"))
    def test_shop_cap(self):
        gid = next(g for g, v in R.GOODS.items() if v["limit_num"] == 2)
        self.assertIsNone(R.check_shop_buy(1, gid, 2, 0, "DAY"))
        self.assertEqual(R.check_shop_buy(1, gid, 1, 2, "DAY"), R.code("err_shop_buy_count_not_enough"))
        self.assertEqual(R.check_shop_buy(1, gid, 3, 0, "DAY"), 702)
        self.assertEqual(R.check_shop_buy(1, "nope", 1, 0), 701)
        st = R.ShopState(); self.assertIsNone(st.buy(1, gid, 2, "DAY")); self.assertEqual(st.buy(1, gid, 1, "DAY"), 702)
        st.reset("WEEK"); self.assertEqual(st.buy(1, gid, 1, "DAY"), 702)
        st.reset("DAY"); self.assertIsNone(st.buy(1, gid, 1, "DAY"))
    def test_cost(self):
        self.assertEqual(R.check_cost({101: 50}, {101: 100}), R.code("err_item_not_enough"))
        self.assertEqual(R.check_cost({}, {102: 1}), 51)
        self.assertIsNone(R.check_cost({101: 100}, {101: 100}))
        res = {101: 10}; self.assertIsNone(R.apply_cost(res, {101: 4})); self.assertEqual(res[101], 6)
        self.assertEqual(R.apply_cost(res, {101: 7}), 51); self.assertEqual(res[101], 6)
if __name__ == "__main__": unittest.main(verbosity=2)
