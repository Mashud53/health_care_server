import app from "./app";
import config from "./app/config";
import { prisma } from "./app/lib/prisma";
import { redisClient } from "./app/lib/redis";
import { seedAdmin, seedDoctor, seedSuperAdmin } from "./app/utils/seed";

const PORT = config.port;

const main = async () => {
	try {
		await redisClient.connect()
		console.log("Redis connected successfull!");
		await prisma.$connect();
		await seedSuperAdmin();
		await seedAdmin();
		await seedDoctor();
		console.log("Connected to the database successfully.");
		app.listen(PORT, () => {
			console.log(`Server is running on port ${PORT}`);
		});
	} catch (error) {
		console.error("Error starting the server:", error);
		await prisma.$disconnect();
		process.exit(1);
	}
};

main();
