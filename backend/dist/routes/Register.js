"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = __importDefault(require("zod"));
const client_1 = require("@prisma/client");
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient({ log: ["query", "info"] });
const RegisterInput = zod_1.default.object({
    organizationName: zod_1.default.string(),
    organizationCode: zod_1.default.string(),
    adminName: zod_1.default.string(),
    adminUsername: zod_1.default.string(),
    adminPassword: zod_1.default.string()
});
router.post("/", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const organizationName = req.body.organizationName;
    const organizationCode = req.body.organizationCode;
    const adminName = req.body.adminName;
    const adminUsername = req.body.adminUsername;
    const adminPassword = req.body.adminPassword;
    const valid = RegisterInput.safeParse({ organizationName, organizationCode, adminName, adminUsername, adminPassword });
    if (valid.success) {
        console.log("input valid");
        console.log(organizationCode);
        const result = yield prisma.organization.findUnique({
            where: {
                code: organizationCode
            }
        });
        console.log("user finding");
        if (result) {
            res.status(401).json({
                msg: "code already being used, please use a different code"
            });
            return;
        }
        if (adminUsername.startsWith(organizationCode)) {
            yield prisma.organization.create({
                data: {
                    code: organizationCode,
                    organizationName: organizationName,
                    admin: {
                        create: {
                            name: adminName,
                            username: adminUsername,
                            password: adminPassword
                        }
                    }
                }
            });
            res.status(200).json({
                msg: "success"
            });
        }
        else {
            res.status(400).json({
                msg: "admin username should begin with organization code"
            });
        }
    }
    else {
        res.status(400).json({
            msg: "Invalid input"
        });
    }
}));
exports.default = router;
