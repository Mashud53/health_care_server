import z, { email } from "zod";

const PatientRegistrationZodSchema = z.object({
	name: z.string(),
	email: z.email(),
	password: z
		.string()
		.min(5, { message: "Password must be at least 5 characters long." })
		.max(16, { message: "Password cannot exceed 16 characters." })
		.regex(/[A-Z]/, {
			message: "Password must contain at least one uppercase letter.",
		})
		.regex(/[a-z]/, {
			message: "Password must contain at least one lowercase letter.",
		})
		.regex(/[0-9]/, { message: "Password must contain at least one number." })
		.regex(/[^A-Za-z0-9]/, {
			message: "Password must contain at least one special character.",
		}),
	patient: z
		.object({
			contactNumber: z.string().optional(),
		})
		.optional(),
});

const LoginZodShemaa = z.object({
	email: z.email(),
	password: z
		.string()
		.min(5, { message: "Password must be at least 5 characters long." })
		.max(16, { message: "Password cannot exceed 16 characters." })
		.regex(/[A-Z]/, {
			message: "Password must contain at least one uppercase letter.",
		})
		.regex(/[a-z]/, {
			message: "Password must contain at least one lowercase letter.",
		})
		.regex(/[0-9]/, { message: "Password must contain at least one number." })
		.regex(/[^A-Za-z0-9]/, {
			message: "Password must contain at least one special character.",
		}),
});
const ResetPasswordZodShemaa = z.object({
	email: z.email(),
	newPassword: z
		.string()
		.min(5, { message: "Password must be at least 5 characters long." })
		.max(16, { message: "Password cannot exceed 16 characters." })
		.regex(/[A-Z]/, {
			message: "Password must contain at least one uppercase letter.",
		})
		.regex(/[a-z]/, {
			message: "Password must contain at least one lowercase letter.",
		})
		.regex(/[0-9]/, { message: "Password must contain at least one number." })
		.regex(/[^A-Za-z0-9]/, {
			message: "Password must contain at least one special character.",
		}),
		otp: z.string().length(6)
});
const ForgotPasswordZodShemaa = z.object({
	email: z.email(),
	
});

export const UserValidation = {
	PatientRegistrationZodSchema,
	LoginZodShemaa,
	ResetPasswordZodShemaa,
	ForgotPasswordZodShemaa
};
