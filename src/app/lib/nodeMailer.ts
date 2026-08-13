import nodmailer from "nodemailer"
import config from "../config"

export const transporter = nodmailer.createTransport({
    service:"gmail",
    auth: {
        user: config.smtp_user,
        pass: config.smtp_password
    }
})

