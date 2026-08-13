import type { Role } from "../../../generated/prisma/browser";

export interface ILoginUserPayload {
	email: string;
	password: string;
}

export interface IRegisterPatientPayload {
	name: string;
	email: string;
	password: string;
	patient: {
		contactNumber?: string
	}
}
export interface IverifiedEmailPayload {
	email: string;
	otp: string;

}

export interface IRequestUser {
	userId: string;
	email: string;
	name: string;
	role: Role;
}

export interface GoogleLoginPayload {
	idToken: string;
}
export interface ForgotPasswordPayload{
	email: string
}

export interface resetPasswordPayload{
	email: string;
	newPassword: string;
	otp: string;
}