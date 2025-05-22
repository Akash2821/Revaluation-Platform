"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const router = (0, express_1.Router)();
const jwtSecret = process.env.JWT_SECRET || "yogiman";
router.get("/", (req, res) => {
    const token = req.headers.authorization;
    try {
        //console.log(token)
        const jwtString = token.split(" ")[1];
        //console.log(jwtString);
        const decodedValue = jsonwebtoken_1.default.verify(jwtString, jwtSecret);
        //console.log(decodedValue);
        res.status(200).json({
            msg: "success",
            name: decodedValue.name,
            username: decodedValue.username,
            type: decodedValue.type,
        });
    }
    catch (error) {
        console.error('JWT verification failed:', error);
        res.status(401).json({
            msg: "Unauthorized",
            error: error.message,
        });
    }
});
exports.default = router;
