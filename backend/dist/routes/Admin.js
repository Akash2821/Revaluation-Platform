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
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient({ log: ["query", "info"] });
const jwtSecret = process.env.JWT_SECRET || "yogiman";
const authorize_1 = __importDefault(require("../middlewares/authorize"));
const adminInput = zod_1.default.object({
    username: zod_1.default.string(),
    password: zod_1.default.string()
});
const addAdminInput = zod_1.default.object({
    name: zod_1.default.string(),
    username: zod_1.default.string(),
    password: zod_1.default.string()
});
const addStudentInput = zod_1.default.object({
    name: zod_1.default.string(),
    username: zod_1.default.string(),
    password: zod_1.default.string()
});
const addTeacherInput = zod_1.default.object({
    name: zod_1.default.string(),
    username: zod_1.default.string(),
    password: zod_1.default.string()
});
const addSubject = zod_1.default.object({
    name: zod_1.default.string(),
    subjectCode: zod_1.default.string()
});
var User;
(function (User) {
    User[User["student"] = 0] = "student";
    User[User["teacher"] = 1] = "teacher";
    User[User["admin"] = 2] = "admin";
})(User || (User = {}));
router.post("/login", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    const password = req.body.password;
    const valid = adminInput.safeParse({ username, password });
    if (valid.success) {
        const result = yield prisma.admin.findUnique({
            where: {
                username: username
            }
        });
        if (result) {
            if (result.password === password) {
                const token = jsonwebtoken_1.default.sign({ username: username, type: User.admin, name: result.name, organizationId: result.organizationId }, jwtSecret);
                res.status(200).json({
                    msg: "success",
                    token: token,
                    type: User.admin,
                    name: result.name,
                });
            }
            else {
                res.status(401).json({
                    msg: "wrong password",
                });
            }
        }
        else {
            res.status(404).json({
                msg: "user does not exist",
            });
        }
    }
    else {
        res.status(400).json({
            msg: "invalid input"
        });
    }
}));
router.post("/add-admin", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    const name = req.body.name;
    const password = req.body.password;
    const organizationId = req.headers.organizationId
        ? parseInt(req.headers.organizationId)
        : 0;
    const valid = addAdminInput.safeParse({ name, username, password });
    if (valid.success) {
        if (!username.startsWith(req.headers.code)) {
            res.status(401).json({
                msg: "it should begin with organization code"
            });
            return;
        }
        const result = yield prisma.admin.findUnique({
            where: {
                username: username
            }
        });
        if (result) {
            res.status(401).json({
                msg: "user already exists"
            });
            return;
        }
        yield prisma.admin.create({
            data: {
                name: name,
                username: username,
                password: password,
                organizationId: organizationId
            }
        });
        res.status(200).json({
            msg: "success"
        });
    }
}));
router.post("/add-teacher", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    const name = req.body.name;
    const password = req.body.password;
    const organizationId = req.headers.organizationId
        ? parseInt(req.headers.organizationId)
        : 0;
    // Validate input using your custom input validation schema (e.g., addTeacherInput)
    const valid = addTeacherInput.safeParse({ name, username, password });
    if (valid.success) {
        if (!username.startsWith(req.headers.code)) {
            res.status(401).json({
                msg: "it should begin with organization code"
            });
            return;
        }
        // Check if teacher with the same username already exists
        const result = yield prisma.teacher.findUnique({
            where: {
                username: username
            }
        });
        if (result) {
            res.status(401).json({
                msg: "Teacher with this username already exists"
            });
            return;
        }
        // Create the new teacher
        yield prisma.teacher.create({
            data: {
                name: name,
                username: username,
                password: password,
                organizationId: organizationId
            }
        });
        res.status(200).json({
            msg: "Teacher added successfully"
        });
    }
    else {
        res.status(400).json({
            msg: "Invalid input",
            errors: valid.error.errors
        });
    }
}));
router.post("/add-student", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    const name = req.body.name;
    const password = req.body.password;
    const organizationId = req.headers.organizationId
        ? parseInt(req.headers.organizationId)
        : 0;
    // Validate input using your custom input validation schema (e.g., addStudentInput)
    const valid = addStudentInput.safeParse({ name, username, password });
    if (valid.success) {
        if (!username.startsWith(req.headers.code)) {
            res.status(401).json({
                msg: "it should begin with organization code"
            });
            return;
        }
        // Check if student with the same username already exists
        const result = yield prisma.student.findUnique({
            where: {
                username: username
            }
        });
        if (result) {
            res.status(401).json({
                msg: "Student with this username already exists"
            });
            return;
        }
        // Create the new student
        yield prisma.student.create({
            data: {
                name: name,
                username: username,
                password: password,
                organizationId: organizationId
            }
        });
        res.status(200).json({
            msg: "Student added successfully"
        });
    }
    else {
        res.status(400).json({
            msg: "Invalid input",
            errors: valid.error.errors
        });
    }
}));
router.post("/add-subject", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const name = req.body.name;
    const subjectCode = req.body.subjectCode;
    const organizationId = req.headers.organizationId
        ? parseInt(req.headers.organizationId)
        : 0;
    const valid = addSubject.safeParse({ name, subjectCode });
    if (valid.success) {
        if (!subjectCode.startsWith(req.headers.code)) {
            res.status(401).json({
                msg: "it should begin with organization code"
            });
            return;
        }
        const result = yield prisma.subject.findUnique({
            where: {
                subjectCode: subjectCode
            }
        });
        if (result) {
            res.status(401).json({
                msg: "Subject with this code already exists"
            });
            return;
        }
        // Create the new student
        const sub = yield prisma.subject.create({
            data: {
                name: name,
                subjectCode: subjectCode,
                organizationId: organizationId
            }
        });
        res.status(200).json({
            msg: "Subject added successfully id is " + sub.id,
            id: sub.id
        });
    }
    else {
        res.status(400).json({
            msg: "Invalid input",
            errors: valid.error.errors
        });
    }
}));
router.post("/remove-admin", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    if (!username) {
        res.status(400).json({
            msg: "Username is required"
        });
        return;
    }
    // Check if the admin exists
    const admin = yield prisma.admin.findUnique({
        where: {
            username: username
        }
    });
    if (!admin) {
        res.status(404).json({
            msg: "Admin not found"
        });
        return;
    }
    // Delete the admin record
    yield prisma.admin.delete({
        where: {
            username: username
        }
    });
    res.status(200).json({
        msg: "Admin removed successfully"
    });
}));
router.post("/remove-teacher", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    if (!username) {
        res.status(400).json({
            msg: "Username is required"
        });
        return;
    }
    // Check if the teacher exists
    const teacher = yield prisma.teacher.findUnique({
        where: {
            username: username
        }
    });
    if (!teacher) {
        res.status(404).json({
            msg: "Teacher not found"
        });
        return;
    }
    // Delete the teacher record
    yield prisma.teacher.delete({
        where: {
            username: username
        }
    });
    res.status(200).json({
        msg: "Teacher removed successfully"
    });
}));
router.post("/remove-student", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const username = req.body.username;
    if (!username) {
        res.status(400).json({
            msg: "Username is required"
        });
        return;
    }
    // Check if the student exists
    const student = yield prisma.student.findUnique({
        where: {
            username: username
        }
    });
    if (!student) {
        res.status(404).json({
            msg: "Student not found"
        });
        return;
    }
    // Delete the student record
    yield prisma.student.delete({
        where: {
            username: username
        }
    });
    res.status(200).json({
        msg: "Student removed successfully"
    });
}));
router.post("/remove-subject", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const subjectCode = req.body.subjectCode;
    if (!subjectCode) {
        res.status(400).json({
            msg: "Invalid Subject Code"
        });
    }
    const subject = yield prisma.subject.findUnique({
        where: {
            subjectCode: subjectCode
        }
    });
    if (!subject) {
        res.status(404).json({
            msg: "Subject not found"
        });
        return;
    }
    yield prisma.subject.delete({
        where: {
            subjectCode: subjectCode
        }
    });
    res.status(200).json({
        msg: "Subject removed successfully"
    });
}));
router.post("/add-exam", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { name, startTime, endTime, revalOpenStart, revalOpenEnd, papers } = req.body;
        const organizationId = req.headers.organizationId
            ? parseInt(req.headers.organizationId)
            : 0;
        // console.log(name);
        // console.log(startTime);
        // console.log(endTime);
        // console.log(organizationId);
        // console.log(!Array.isArray(papers))
        // console.log(papers.length !== 0)
        if (!name || !startTime || !endTime || !organizationId || !Array.isArray(papers) || papers.length === 0) {
            res.status(400).json({ message: "Missing or invalid required fields" });
            return;
        }
        const exam = yield prisma.exam.create({
            data: {
                name,
                startTime: new Date(startTime),
                endTime: new Date(endTime),
                revalOpenStart: revalOpenStart ? new Date(revalOpenStart) : null,
                revalOpenEnd: revalOpenEnd ? new Date(revalOpenEnd) : null,
                organizationId,
                paper: {
                    create: papers.map((paper) => ({
                        marks: parseInt(paper.maxMarks, 10),
                        questionPaper: Buffer.from(paper.questionPaper, "base64"),
                        subject: {
                            connect: { id: parseInt(paper.subjectId, 10) },
                        },
                    })),
                },
            },
        });
        res.status(201).json({ message: "Exam created successfully", exam });
    }
    catch (error) {
        console.error("Error adding exam:", error);
        res.status(500).json({ message: "An error occurred while adding the exam" });
    }
}));
router.post("/add-answersheet", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { marksScored, answerSheet, paperId, studentId } = req.body;
        const organizationId = req.headers.organizationId
            ? parseInt(req.headers.organizationId)
            : 0;
        if (!marksScored || !answerSheet || !paperId || !studentId || !organizationId) {
            res.status(400).json({ message: "Missing or invalid required fields" });
            return;
        }
        const student = yield prisma.student.findFirst({
            where: {
                id: parseInt(studentId, 10),
                organizationId
            }
        });
        if (!student) {
            res.status(404).json({ message: "Student not found in this organization" });
            return;
        }
        const paper = yield prisma.paper.findFirst({
            where: {
                id: parseInt(paperId, 10),
                exam: {
                    organizationId
                }
            },
            include: {
                exam: true
            }
        });
        if (!paper) {
            res.status(404).json({ message: "Paper not found in this organization" });
            return;
        }
        if (parseInt(marksScored, 10) > paper.marks) {
            res.status(400).json({ message: "Marks scored cannot be greater than maximum marks" });
            return;
        }
        const answersheet = yield prisma.answerSheets.create({
            data: {
                marksScored: parseInt(marksScored, 10),
                answerPaper: Buffer.from(answerSheet, "base64"),
                paperId: parseInt(paperId, 10),
                studentId: parseInt(studentId, 10),
                applyReval: false,
                RevalDone: false
            }
        });
        res.status(201).json({ message: "Answer sheet added successfully", answersheet });
    }
    catch (error) {
        console.error("Error adding answer sheet:", error);
        res.status(500).json({ message: "An error occurred while adding the answer sheet" });
    }
}));
exports.default = router;
