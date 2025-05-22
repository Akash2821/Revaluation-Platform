import {NextFunction} from "express";
import jwt, {JwtPayload} from "jsonwebtoken";
const jwtSecret = process.env.JWT_SECRET || "yogiman";


function authorize(req: any, res: any, next: NextFunction) {
    const token = req.headers.authorization;

    // Ensure token is a string
    if (typeof token !== 'string') {
        return res.status(401).json({
            msg: "Unauthorized, no token provided"
        });
    }

    try {
        const jwtString = token.split(" ")[1]; // Now safe to use split
        const decodedValue = jwt.verify(jwtString, jwtSecret) as JwtPayload;
        req.headers.organizationId = parseInt(decodedValue.organizationId);
        req.headers.code = decodedValue.username.substring(0, 4);
        req.headers.username = decodedValue.username;
        next();
    } catch (error: any) {
        console.error('JWT verification failed:', error);
        res.status(401).json({
            msg: "Unauthorized",
            error: error.message,
        });
    }
}



export default authorize;