import { Router } from "express";
const router = Router();

// Features
import user from "./user/route";
import auth from "./auth/route";
import products from "./products/route";
import category from "./category/route";
import wishlist from "./wishlist/route";
import coupon from "./coupons/route";

router.use("/users", user);
router.use("/auth", auth);
router.use("/category", category);
router.use("/products", products);
router.use("/wishlist", wishlist);
router.use("/coupons", coupon);

export default router;
