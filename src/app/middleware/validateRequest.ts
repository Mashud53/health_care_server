import { NextFunction, Request, Response } from "express";
import { catchAsync } from "../utils/catchAsync";
import z from "zod";

export const validateRequest = (zodSchema: z.ZodObject) => {
    return catchAsync((req: Request, res: Response, next: NextFunction) => {
        const paylod = req.body ?? {};
        const result = zodSchema.safeParse(paylod)
        if (!result.success) {
            throw new Error(result.error.issues[0].message);
        }

        req.body = result.data;

        next();
    });
};