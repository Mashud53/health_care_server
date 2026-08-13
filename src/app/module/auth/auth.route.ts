import { NextFunction, Request, Response, Router } from "express";
import { Role } from "../../../generated/prisma/enums";
import { auth } from "../../middleware/checkAuth";
import { AuthController } from "./auth.controller";
import { UserValidation } from "./auth.validation";
import { validateRequest } from "../../middleware/validateRequest";

const router = Router();

router.post(
	"/register",
	validateRequest(UserValidation.PatientRegistrationZodSchema),
	AuthController.registerPatient,
);
router.post(
	"/verify-email",
	validateRequest(UserValidation.PatientEmilVerifySchema),
	AuthController.verifiedPatientEmail,
);

router.post("/login",validateRequest(UserValidation.LoginZodShemaa), AuthController.loginUser);

router.get(
	"/me",
	auth(Role.ADMIN, Role.DOCTOR, Role.PATIENT, Role.SUPER_ADMIN),
	AuthController.getMe,
);
router.post("/refresh-token", AuthController.refreshToken);
router.post("/google", AuthController.googleLogin);
router.post("/forgot-password",
	validateRequest(UserValidation.ForgotPasswordZodShemaa), AuthController.forgotPassword)
router.post("/reset-password",
	validateRequest(UserValidation.ResetPasswordZodShemaa), AuthController.resetPassword)



export const AuthRoutes = router;
