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
const authorize_1 = __importDefault(require("../middlewares/authorize"));
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient({ log: ["query", "info"] });
const jwtSecret = process.env.JWT_SECRET || "yogiman";
const TeacherInput = zod_1.default.object({
    username: zod_1.default.string(),
    password: zod_1.default.string()
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
    const valid = TeacherInput.safeParse({ username, password });
    if (valid.success) {
        const result = yield prisma.teacher.findUnique({
            where: {
                username: username
            }
        });
        if (result) {
            if (result.password === password) {
                const token = jsonwebtoken_1.default.sign({ username: username, type: User.teacher, name: result.name, organizationId: result.organizationId }, jwtSecret);
                res.status(200).json({
                    msg: "success",
                    token: token,
                    type: User.teacher,
                    name: result.name
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
router.post("/add-subject", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const subjectCode = req.body.subjectCode; // Expecting teacherId and subjectCode in the request body
    const teacherUsername = req.headers.username;
    // Step 1: Validate the input
    if (!teacherUsername || !subjectCode) {
        res.status(400).json({
            msg: "Teacher ID and subject code are required"
        });
        return;
    }
    // Step 2: Check if the subject with the given subjectCode exists
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
    // Step 3: Check if the teacher exists
    const teacher = yield prisma.teacher.findUnique({
        where: {
            username: teacherUsername
        }
    });
    if (!teacher) {
        res.status(404).json({
            msg: "Teacher not found"
        });
        return;
    }
    // Step 4: Ensure the teacher and subject belong to the same organization (optional, depending on your business logic)
    if (teacher.organizationId !== subject.organizationId) {
        res.status(403).json({
            msg: "Teacher and subject must belong to the same organization"
        });
        return;
    }
    // Step 5: Add the teacher to the subject (many-to-many relationship)
    yield prisma.subject.update({
        where: {
            id: subject.id
        },
        data: {
            teachers: {
                connect: { id: teacher.id } // Connect the teacher to the subject
            }
        }
    });
    res.status(200).json({
        msg: "Teacher successfully assigned to the subject"
    });
}));
router.post("/remove-subject", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const subjectCode = req.body.subjectCode; // Expecting subjectCode in the request body
    const teacherUsername = req.headers.username;
    // Step 1: Validate the input
    if (!teacherUsername || !subjectCode) {
        res.status(400).json({
            msg: "Teacher username and subject code are required"
        });
        return;
    }
    // Step 2: Check if the subject with the given subjectCode exists
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
    // Step 3: Check if the teacher exists
    const teacher = yield prisma.teacher.findUnique({
        where: {
            username: teacherUsername
        }
    });
    if (!teacher) {
        res.status(404).json({
            msg: "Teacher not found"
        });
        return;
    }
    // Step 4: Ensure the teacher and subject belong to the same organization (optional, depending on your business logic)
    if (teacher.organizationId !== subject.organizationId) {
        res.status(403).json({
            msg: "Teacher and subject must belong to the same organization"
        });
        return;
    }
    // Step 5: Remove the teacher from the subject (disconnect the teacher from the subject)
    yield prisma.subject.update({
        where: {
            id: subject.id
        },
        data: {
            teachers: {
                disconnect: { id: teacher.id } // Disconnect the teacher from the subject
            }
        }
    });
    res.status(200).json({
        msg: "Teacher successfully removed from the subject"
    });
    return;
}));
router.get("/subjects", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const subjectList = prisma.
        teacher.findUnique({
        where: {
            username: req.headers.username
        },
        include: {
            subjects: {
                select: {
                    name: true,
                    subjectCode: true
                }
            }
        }
    }).then(teacher => {
        if (!teacher) {
            res.status(404).json({
                msg: "Teacher not found"
            });
            return;
        }
        res.status(200).json({
            msg: "success",
            subjects: teacher.subjects
        });
    }).catch(error => {
        res.status(500).json({
            msg: "Internal server error",
            error: error.message
        });
    });
}));
router.post("/papers", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const subjectCode = req.body.subjectCode;
    const teacherUsername = req.headers.username;
    if (!teacherUsername || !subjectCode) {
        res.status(400).json({
            msg: "Teacher username and subject code are required"
        });
        return;
    }
    const teacher = yield prisma.teacher.findUnique({
        where: {
            username: teacherUsername
        }
    });
    if (!teacher) {
        res.status(404).json({
            msg: "Teacher not found"
        });
        return;
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
    if (teacher.organizationId !== subject.organizationId) {
        res.status(403).json({
            msg: "Teacher and subject must belong to the same organization"
        });
        return;
    }
    const answerSheets = yield prisma.answerSheets.findMany({
        where: {
            paper: {
                subjectId: subject.id
            },
            applyReval: true,
            RevalDone: false
        },
        include: {
            paper: true,
            student: true
        }
    });
    res.status(200).json({
        answerSheets: answerSheets
    });
}));
router.post("/update-marks", authorize_1.default, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { answerSheetId, newMarks } = req.body;
        const organizationId = req.headers.organizationId
            ? parseInt(req.headers.organizationId)
            : 0;
        if (!answerSheetId || !newMarks || isNaN(newMarks)) {
            res.status(400).json({ message: "Missing or invalid required fields" });
            return;
        }
        const answerSheet = yield prisma.answerSheets.findFirst({
            where: {
                id: parseInt(answerSheetId, 10),
                paper: {
                    exam: {
                        organizationId
                    }
                }
            },
            include: {
                paper: true
            }
        });
        if (!answerSheet) {
            res.status(404).json({ message: "Answer sheet not found in this organization" });
            return;
        }
        if (parseInt(newMarks, 10) > answerSheet.paper.marks) {
            res.status(400).json({ message: "New marks cannot be greater than maximum marks" });
            return;
        }
        const updatedAnswerSheet = yield prisma.answerSheets.update({
            where: {
                id: parseInt(answerSheetId, 10)
            },
            data: {
                marksScored: parseInt(newMarks, 10),
                RevalDone: true
            }
        });
        res.status(200).json({ message: "Marks updated successfully", updatedAnswerSheet });
    }
    catch (error) {
        console.error("Error updating marks:", error);
        res.status(500).json({ message: "An error occurred while updating the marks" });
    }
}));
exports.default = router;
