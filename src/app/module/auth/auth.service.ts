/** biome-ignore-all lint/style/useConst: <explanation> */
import bcrypt from "bcryptjs";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import {
	AuthProvider,
	Role,
	UserStatus,
} from "../../../generated/prisma/enums";
import config from "../../config";
import { prisma } from "../../lib/prisma";
import { jwtUtils } from "../../utils/jwt";
import type {
	ForgotPasswordPayload,
	GoogleLoginPayload,
	ILoginUserPayload,
	IRegisterPatientPayload,
	IRequestUser,
	IverifiedEmailPayload,
	resetPasswordPayload,
} from "./auth.interface";
import { OAuth2Client, type TokenPayload } from "google-auth-library";
import { googleClient } from "../../lib/googleAuth";
import crypto from "crypto";
import { redisClient } from "../../lib/redis";
import { number } from "zod";
import { transporter } from "../../lib/nodeMailer";
import ejs, { name } from "ejs";
import path from "path";

const registerPatient = async (payload: IRegisterPatientPayload) => {
	const { name, password, patient: patinetData } = payload;
	const email = payload.email.trim().toLowerCase();

	const isUserExists = await prisma.user.findUnique({
		where: { email },
	});

	if (isUserExists) {
		throw new Error("User with this email already exists");
	}

	const hashedPassword = await bcrypt.hash(password, 8);

	const otpKey = `patient-registration-otp: ${email}`;
	const otp = crypto.randomInt(10000, 1000000).toString();
	const expirationSeconds = 5 * 60;

	await redisClient.set(otpKey, otp, {
		expiration: {
			type: "EX",
			value: expirationSeconds,
		},
	});

	const patientRegistrationKey = `patient-registration-data: ${email}`;
	const redisUserDataPaylod = {
		name,
		email,
		password: hashedPassword,
		patient: patinetData,
	};

	await redisClient.set(
		patientRegistrationKey,
		JSON.stringify(redisUserDataPaylod),
		{
			expiration: {
				type: "EX",
				value: expirationSeconds,
			},
		},
	);
	const templatePath = path.join(
		process.cwd(),
		"src/app/templates/registration-user-otp.ejs",
	);

	const html = await ejs.renderFile(templatePath, {
		name: name,
		email: email,
		otp: otp,
		expirationMinutes: expirationSeconds / 60,
	});

	await transporter.sendMail({
		from: config.email_sender,
		to: email,
		subject: "Email Verification",
		// text:`Your otp is ${otp}`
		// html:`<h1>Your otp is ${otp}</h1>`
		html,
	});
};
const verifiedPatientEmil = async (payload: IverifiedEmailPayload) => {
	const otp = payload.otp;
	const email = payload.email.trim().toLowerCase();

	const isUserExist = await prisma.user.findUnique({
		where: { email },
	});

	if (isUserExist?.status === "BLOCKED") {
		throw new Error("User is blocked");
	}
	if (isUserExist?.emailVerified) {
		throw new Error("User already verified");
	}
	if (isUserExist?.isDeleted || isUserExist?.status === "DELETED") {
		throw new Error("User is deleted");
	}

	const otpKey = `patient-registration-otp: ${email}`;

	const redisOtp = await redisClient.get(otpKey);

	if (!redisOtp) {
		throw new Error("Invalid OTP");
	}
	if (redisOtp !== otp) {
		throw new Error("OTP does not matched");
	}

	const patientRegistrationKey = `patient-registration-data: ${email}`;

	const redisPatientData = await redisClient.get(patientRegistrationKey);

	if (!redisPatientData) {
		throw new Error("User doesn't exist");
	}

	const patientPaylod: IRegisterPatientPayload = JSON.parse(redisPatientData);
	const createdUser = await prisma.user.create({
		data: {
			name: patientPaylod.name,
			email: patientPaylod.email,
			password: patientPaylod.password,
			role: Role.PATIENT,
			status: UserStatus.ACTIVE,
			emailVerified: true,
			patient: {
				create: {
					name: patientPaylod.name,
					email: patientPaylod.email,
					contactNumber: patientPaylod?.patient?.contactNumber || "",
				},
			},
		},
		omit: { password: true },
		include: { patient: true },
	});

	await redisClient.del([otpKey]);
	await redisClient.del([patientRegistrationKey]);

	const templatePath = path.join(
		process.cwd(),
		"src/app/templates/welcome-email.ejs",
	);
	const html = await ejs.renderFile(templatePath, {
		name: createdUser.name,
	});
	await transporter.sendMail({
		from: config.email_sender,
		to: email,
		subject: "Welcom to Health Care",
		// text:`Your otp is ${otp}`
		// html:`<h1>Your otp is ${otp}</h1>`
		html,
	});

	const { patient, ...user } = createdUser;
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		user,
		patient,
		accessToken,
		refreshToken,
	};
};

const loginUser = async (payload: ILoginUserPayload) => {
	const { password } = payload;
	const email = payload.email.trim().toLowerCase();

	const user = await prisma.user.findUnique({
		where: { email },
	});

	if (!user) {
		throw new Error("User not found");
	}

	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	if (user.password === null && user.googleId !== null) {
		throw new Error("User Already Has account, try to login with google");
	}

	const isPasswordMatched = await bcrypt.compare(
		password,
		user.password as string,
	);

	if (!isPasswordMatched) {
		throw new Error("Invalid credentials");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const getMe = async (user: IRequestUser) => {
	const isUserExists = await prisma.user.findUnique({
		where: {
			id: user.userId,
		},
		include: {
			patient: true,
		},
		omit: {
			password: true,
		},
	});

	if (!isUserExists) {
		throw new Error("User not found");
	}

	return isUserExists;
};

const refreshToken = async (token: string) => {
	const verifiedRefreshToken = jwtUtils.verifyToken(
		token,
		config.jwt_refresh_secret,
	);

	if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
		throw new Error(
			config.node_env === "development"
				? verifiedRefreshToken.error
				: "Invalid refresh token",
		);
	}

	const data = verifiedRefreshToken.data as JwtPayload;

	const user = await prisma.user.findUnique({
		where: { id: data.userId },
	});

	if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
		throw new Error("User is inactive or not found");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const googleLogin = async (payload: GoogleLoginPayload) => {
	let googleIdTokenPaylod: TokenPayload | null | undefined = null;
	try {
		const ticket = await googleClient.verifyIdToken({
			idToken: payload.idToken,
			audience: config.google_client_id,
		});

		googleIdTokenPaylod = ticket.getPayload();
	} catch (error) {
		console.log("Google ID token verification Failed", error);
		throw new Error("Invalied or Expired Google ID Token");
	}

	if (!googleIdTokenPaylod) {
		throw new Error("Invalied or Expired Google ID Token");
	}

	if (!googleIdTokenPaylod.email) {
		throw new Error("Google Email not found");
	}
	console.log(googleIdTokenPaylod.name, "user name");
	if (!googleIdTokenPaylod.name) {
		throw new Error("Google name not found");
	}
	const ifPaatientExitstWithGoogleAuth = await prisma.user.findUnique({
		where: {
			email: googleIdTokenPaylod.email,
			role: Role.PATIENT,
			googleId: googleIdTokenPaylod.sub,
		},
	});

	let user = ifPaatientExitstWithGoogleAuth;

	if (!ifPaatientExitstWithGoogleAuth) {
		const ifPatientExistWithCredential = await prisma.user.findUnique({
			where: {
				email: googleIdTokenPaylod.email,
				role: Role.PATIENT,
				authProvider: AuthProvider.CREDENTIAL,
			},
		});
		if (ifPatientExistWithCredential) {
			if (!ifPatientExistWithCredential.emailVerified) {
				throw new Error("Emil not verified!");
			}
			if (ifPatientExistWithCredential.status === "BLOCKED") {
				throw new Error("User is Blocked");
			}

			if (
				ifPatientExistWithCredential.isDeleted ||
				ifPatientExistWithCredential.status === UserStatus.DELETED
			) {
				throw new Error("User is Deleted");
			}
			user = await prisma.user.update({
				where: {
					id: ifPatientExistWithCredential.id,
				},
				data: {
					googleId: googleIdTokenPaylod.sub,
				},
			});
		} else {
			// google register
			user = await prisma.user.create({
				data: {
					name: googleIdTokenPaylod.name,
					email: googleIdTokenPaylod.email,
					role: Role.PATIENT,
					googleId: googleIdTokenPaylod.sub,
					authProvider: AuthProvider.GOOGLE,
					emailVerified: googleIdTokenPaylod.email_verified,
					patient: {
						create: {
							name: googleIdTokenPaylod.name,
							email: googleIdTokenPaylod.email,
						},
					},
				},
			});
			const templatePath = path.join(
				process.cwd(),
				"src/app/templates/welcome-email.ejs",
			);
			const html = await ejs.renderFile(templatePath, {
				name: user.name,
			});
			await transporter.sendMail({
				from: config.email_sender,
				to: user.email,
				subject: "Welcom to Health Care",
				// text:`Your otp is ${otp}`
				// html:`<h1>Your otp is ${otp}</h1>`
				html,
			});
		}
	}
	if (!user) {
		throw new Error("user not found");
	}

	if (user.status === "BLOCKED") {
		throw new Error("User is Blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is Deleted");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};
const forgotPassword = async (payload: ForgotPasswordPayload) => {
	const { email } = payload;
	const isUserExist = await prisma.user.findUnique({
		where: { email },
	});
	if (!isUserExist) {
		throw new Error("User not found");
	}
	if (isUserExist.status === "BLOCKED") {
		throw new Error("User is blocked");
	}
	if (!isUserExist.emailVerified) {
		throw new Error("User not verified");
	}
	if (isUserExist.isDeleted || isUserExist.status === "DELETED") {
		throw new Error("User is deleted");
	}
	if (isUserExist.authProvider !== "CREDENTIAL") {
		throw new Error("User has account with google");
	}
	const otp = crypto.randomInt(10000, 1000000).toString();
	const key = `forgot-password-otp: ${isUserExist.email}`;
	await redisClient.set(key, otp, {
		expiration: {
			type: "EX",
			value: 5 * 60,
		},
	});
	const templatePath = path.join(
		process.cwd(),
		"src/app/templates/forgot-password.ejs",
	);
	const html = await ejs.renderFile(templatePath, {
		otp: otp,
	});

	await transporter.sendMail({
		from: config.email_sender,
		to: isUserExist.email,
		subject: "Forgot Password",
		// text:`Your otp is ${otp}`
		// html:`<h1>Your otp is ${otp}</h1>`
		html,
	});
};
const resetPassword = async (payload: resetPasswordPayload) => {
	const { email, newPassword, otp } = payload;
	const isUserExist = await prisma.user.findUnique({
		where: { email },
	});
	if (!isUserExist) {
		throw new Error("User not found");
	}
	if (isUserExist.status === "BLOCKED") {
		throw new Error("User is blocked");
	}
	if (!isUserExist.emailVerified) {
		throw new Error("User not verified");
	}
	if (isUserExist.isDeleted || isUserExist.status === "DELETED") {
		throw new Error("User is deleted");
	}
	if (isUserExist.authProvider !== "CREDENTIAL") {
		throw new Error("User has account with google");
	}
	const key = `forgot-password-otp: ${isUserExist.email}`;

	const redisOtp = await redisClient.get(key);
	if (!redisOtp) {
		throw new Error("Invalid OTP");
	}
	if (redisOtp !== otp) {
		throw new Error("OTP does not matched");
	}

	const hashNewPassword = await bcrypt.hash(
		newPassword,
		Number(config.bcrypt_salt_rounds),
	);
	await prisma.user.update({
		where: {
			email: isUserExist.email,
		},
		data: {
			password: hashNewPassword,
		},
	});

	await redisClient.del([key]);
	const templatePath = path.join(
		process.cwd(),
		"src/app/templates/reset-password-success.ejs",
	);
	const html = await ejs.renderFile(templatePath, {
		name: isUserExist.name,
	});

	await transporter.sendMail({
		from: config.email_sender,
		to: isUserExist.email,
		subject: "Password Chaanged",
		// text:`Your otp is ${otp}`
		// html:`<h1>Your otp is ${otp}</h1>`
		html,
	});
};

export const AuthService = {
	registerPatient,
	verifiedPatientEmil,
	loginUser,
	getMe,
	refreshToken,
	googleLogin,
	forgotPassword,
	resetPassword,
};
