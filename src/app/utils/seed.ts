import { Role } from "../../generated/prisma/enums";
import config from "../config";
import { prisma } from "../lib/prisma";
import bcrypt from "bcryptjs";

export const seedSuperAdmin = async () => {
	try {
		const isSuperAdminExist = await prisma.user.findFirst({
			where: {
				role: Role.SUPER_ADMIN,
			},
		});
		if (isSuperAdminExist) {
			console.log("Super admin Already exist!");
			return;
		}

		const name = config.super_admin_name;
		const email = config.super_admin_email;
		const password = config.super_admin_password;

		if (!name || !email || !password) {
			throw new Error("super admin name, email, password missing in env");
		}

		const hashPassword = await bcrypt.hash(
			password,
			Number(config.bcrypt_salt_rounds),
		);
		const superAdmin = await prisma.user.create({
			data: {
				name,
				email,
				password: hashPassword,
				role: Role.SUPER_ADMIN,
				emailVerified: true,
			},
		});

		console.log("Super admin Created:", superAdmin);
	} catch (error) {
		console.log("Errore seeding Super Admin", error);
		await prisma.user.delete({
			where: {
				email: config.super_admin_email,
			},
		});
	}
};

export const seedAdmin = async () => {
	try {
		const isAdminExist = await prisma.user.findFirst({
			where: {
				role: Role.ADMIN,
			},
		});
		if (isAdminExist) {
			console.log("Admin Already Exist");
			return;
		}
		const name = config.tester_admin_nme;
		const email = config.tester_admin_email;
		const password = config.tester_admin_password;

		if (!name || !email || !password) {
			throw new Error("super admin name, email, password missing in env");
		}
		const hashPassword = await bcrypt.hash(
			password,
			Number(process.env.BCRYPT_SALT_ROUNDS),
		);

		const admin = await prisma.user.create({
			data: {
				name,
				email,
				password: hashPassword,
				role: Role.ADMIN,
				emailVerified: true,
			},
		});

		console.log("testing admin created :", admin);
	} catch (error) {
		console.log("Error Seeding Admin", error);
		await prisma.user.delete({
			where:{
				email: config.tester_admin_email
			}
		})
	}
};

export const seedDoctor = async () => {
	try {
		const isDorctorExist = await prisma.user.findFirst({
		where: {
			role: Role.DOCTOR,
		},
	});
	if (isDorctorExist) {
		console.log("Doctor already exist");
		return;
	}

	const name = config.tester_doctor_name;
	const email = config.tester_doctor_emil;
	const password = config.tester_doctor_password;

	if (!name || !email || !password) {
		throw new Error("super admin name, email, password missing in env");
	}
	const hashPassword = await bcrypt.hash(
		password,
		Number(config.bcrypt_salt_rounds),
	);

	const doctor = await prisma.user.create({
		data: {
			name,
			email,
			password: hashPassword,
			role: Role.DOCTOR,
			emailVerified: true,
		},
	});
	console.log("Testing doctor created successfull: ", doctor);
		
	} catch (error) {
		console.log("Error form seed Doctor: ", error);
		await prisma.user.delete({
			where:{
				email: config.tester_doctor_emil
			}
		})
		
	}
};
