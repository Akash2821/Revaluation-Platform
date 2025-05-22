"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwtSecret = process.env.JWT_SECRET || "yogiman";
function authorize(req, res, next) {
    const token = req.headers.authorization;
    // Ensure token is a string
    if (typeof token !== 'string') {
        return res.status(401).json({
            msg: "Unauthorized, no token provided"
        });
    }
    try {
        const jwtString = token.split(" ")[1]; // Now safe to use split
        const decodedValue = jsonwebtoken_1.default.verify(jwtString, jwtSecret);
        req.headers.organizationId = parseInt(decodedValue.organizationId);
        req.headers.code = decodedValue.username.substring(0, 4);
        req.headers.username = decodedValue.username;
        next();
    }
    catch (error) {
        console.error('JWT verification failed:', error);
        res.status(401).json({
            msg: "Unauthorized",
            error: error.message,
        });
    }
}
exports.default = authorize;
