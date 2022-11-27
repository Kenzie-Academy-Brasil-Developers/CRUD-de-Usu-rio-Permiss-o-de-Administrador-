import { Router } from "express";

const router = Router();

router.get("", listUserController);
router.post("", createUserController);
router.get("/profile", profileUserController);
router.patch("/:id", updateUserController);
router.delete("/:id", deleteUserController);

export default router;
