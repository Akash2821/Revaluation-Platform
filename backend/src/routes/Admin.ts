import {Router} from 'express';
import zod from "zod";
import {PrismaClient} from "@prisma/client";
import jwt from "jsonwebtoken";
import { Request, Response } from 'express';
const router : Router = Router();
const prisma: PrismaClient= new PrismaClient({log:["query","info"]});
const jwtSecret = process.env.JWT_SECRET || "yogiman";

import authorize from "../middlewares/authorize";

const adminInput = zod.object({
    username : zod.string(),
    password: zod.string()
})

const addAdminInput = zod.object({
    name : zod.string(),
    username: zod.string(),
    password : zod.string()
})

const addStudentInput = zod.object({
    name : zod.string(),
    username: zod.string(),
    password : zod.string()
})
const addTeacherInput = zod.object({
    name : zod.string(),
    username: zod.string(),
    password : zod.string()
})

const addSubject = zod.object({
    name : zod.string(),
    subjectCode : zod.string()
})

enum User{
    student,
    teacher,
    admin
}

router.post("/login",async (req,res)=>{
    const username : string = req.body.username;
    const password: string = req.body.password;
    const valid = adminInput.safeParse({username, password});
    if(valid.success){

        const result = await prisma.admin.findUnique({
            where:{
                username:username
            }
        });

        if(result){
            if(result.password === password){
                const token = jwt.sign({username:username,type:User.admin,name:result.name,organizationId:result.organizationId},jwtSecret);
                res.status(200).json({
                    msg : "success",
                    token : token,
                    type : User.admin,
                    name : result.name,
                })
            }
            else{
                res.status(401).json({
                    msg : "wrong password",
                })
            }
        }
        else{
            res.status(404).json({
                msg : "user does not exist",
            })
        }
    }
    else{
        res.status(400).json({
            msg : "invalid input"
        })
    }
})



router.post("/add-admin",authorize,async (req,res)=>{
    const username = req.body.username;
    const name = req.body.name;
    const password = req.body.password;
    const organizationId: number  = req.headers.organizationId
        ? parseInt(req.headers.organizationId as string)
        : 0;

    const valid = addAdminInput.safeParse({name,username, password});
    if(valid.success){
        if(!username.startsWith(req.headers.code)){
            res.status(401).json({
                msg : "it should begin with organization code"
            })
            return;
        }
        const result = await prisma.admin.findUnique({
            where : {
                username:username
            }
        })
        if(result){
            res.status(401).json({
                msg : "user already exists"
            })
            return;
        }
        await prisma.admin.create({
            data : {
                name : name,
                username : username,
                password : password,
                organizationId : organizationId
            }
        })
        res.status(200).json({
            msg : "success"
        })
    }
})


router.post("/add-teacher", authorize, async (req, res) => {
    const username = req.body.username;
    const name = req.body.name;
    const password = req.body.password;
    const organizationId: number  = req.headers.organizationId
        ? parseInt(req.headers.organizationId as string)
        : 0;
    // Validate input using your custom input validation schema (e.g., addTeacherInput)
    const valid = addTeacherInput.safeParse({ name, username, password });

    if (valid.success) {
        if(!username.startsWith(req.headers.code)){
            res.status(401).json({
                msg : "it should begin with organization code"
            })
            return;
        }
        // Check if teacher with the same username already exists
        const result = await prisma.teacher.findUnique({
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
        await prisma.teacher.create({
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
    } else {
        res.status(400).json({
            msg: "Invalid input",
            errors: valid.error.errors
        });
    }
});



router.post("/add-student", authorize, async (req, res) => {
    const username = req.body.username;
    const name = req.body.name;
    const password = req.body.password;
    const organizationId: number  = req.headers.organizationId
        ? parseInt(req.headers.organizationId as string)
        : 0;
    // Validate input using your custom input validation schema (e.g., addStudentInput)
    const valid = addStudentInput.safeParse({ name, username, password });

    if (valid.success) {
        if(!username.startsWith(req.headers.code)){
            res.status(401).json({
                msg : "it should begin with organization code"
            })
            return;
        }
        // Check if student with the same username already exists
        const result = await prisma.student.findUnique({
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
        await prisma.student.create({
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
    } else {
        res.status(400).json({
            msg: "Invalid input",
            errors: valid.error.errors
        });
    }
});



router.post("/add-subject",authorize,async (req,res)=>{
    const name = req.body.name;
    const subjectCode = req.body.subjectCode;
    const organizationId: number  = req.headers.organizationId
        ? parseInt(req.headers.organizationId as string)
        : 0;
    const valid = addSubject.safeParse({name,subjectCode});
    if(valid.success){
        if(!subjectCode.startsWith(req.headers.code)){
            res.status(401).json({
                msg : "it should begin with organization code"
            })
            return;
        }
        const result = await prisma.subject.findUnique({
            where: {
                subjectCode : subjectCode
            }
        });

        if (result) {
            res.status(401).json({
                msg: "Subject with this code already exists"
            });
            return;
        }

        // Create the new student
        const sub =  await prisma.subject.create({
            data: {
                name : name,
                subjectCode : subjectCode,
                organizationId : organizationId
            }
        });

        res.status(200).json({
            msg: "Subject added successfully id is " + sub.id,
            id : sub.id
        });
    }
    else{
        res.status(400).json({
            msg: "Invalid input",
            errors: valid.error.errors
        });
    }
})

router.post("/remove-admin", authorize,async (req,res) => {
    const username = req.body.username;

    if (!username) {
        res.status(400).json({
            msg: "Username is required"
        });
        return;
    }

    // Check if the admin exists
    const admin = await prisma.admin.findUnique({
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
    await prisma.admin.delete({
        where: {
            username: username
        }
    });

    res.status(200).json({
        msg: "Admin removed successfully"
    });
})


router.post("/remove-teacher", authorize, async (req, res) => {
    const username = req.body.username;

    if (!username) {
        res.status(400).json({
            msg: "Username is required"
        });
        return;
    }

    // Check if the teacher exists
    const teacher = await prisma.teacher.findUnique({
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
    await prisma.teacher.delete({
        where: {
            username: username
        }
    });

    res.status(200).json({
        msg: "Teacher removed successfully"
    });
});


router.post("/remove-student", authorize, async (req, res) => {
    const username = req.body.username;

    if (!username) {
        res.status(400).json({
            msg: "Username is required"
        });
        return;
    }

    // Check if the student exists
    const student = await prisma.student.findUnique({
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
    await prisma.student.delete({
        where: {
            username: username
        }
    });

    res.status(200).json({
        msg: "Student removed successfully"
    });
});

router.post("/remove-subject", authorize, async (req,res)=>{
    const subjectCode = req.body.subjectCode;
    if (!subjectCode) {
        res.status(400).json({
            msg: "Invalid Subject Code"
        })
    }
    const subject = await prisma.subject.findUnique({
        where : {
            subjectCode : subjectCode
        }
    })
    if (!subject){
        res.status(404).json({
            msg: "Subject not found"
        })
        return ;
    }

    await prisma.subject.delete({
        where : {
            subjectCode : subjectCode
        }
    })
    res.status(200).json({
        msg: "Subject removed successfully"
    })
})



router.post("/add-exam", authorize, async (req: Request, res: Response) => {
    try {
        const { name, startTime, endTime, revalOpenStart, revalOpenEnd, papers } = req.body;
        const organizationId: number  = req.headers.organizationId
            ? parseInt(req.headers.organizationId as string)
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

        const exam = await prisma.exam.create({
            data: {
                name,
                startTime: new Date(startTime),
                endTime: new Date(endTime),
                revalOpenStart: revalOpenStart ? new Date(revalOpenStart) : null,
                revalOpenEnd: revalOpenEnd ? new Date(revalOpenEnd) : null,
                organizationId,
                paper: {
                    create: papers.map((paper: { maxMarks: string; questionPaper: string; subjectId: string }) => ({
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
    } catch (error) {
        console.error("Error adding exam:", error);
        res.status(500).json({ message: "An error occurred while adding the exam" });
    }
});

router.post("/add-answersheet", authorize, async (req: Request, res: Response) => {
    try {
        const { marksScored, answerSheet, paperId, studentId } = req.body;
        const organizationId: number  = req.headers.organizationId
            ? parseInt(req.headers.organizationId as string)
            : 0;

        if (!marksScored || !answerSheet || !paperId || !studentId || !organizationId) {
            res.status(400).json({ message: "Missing or invalid required fields" });
            return;
        }

        const student = await prisma.student.findFirst({
            where: {
                id: parseInt(studentId, 10),
                organizationId
            }
        });

        if (!student) {
            res.status(404).json({ message: "Student not found in this organization" });
            return;
        }

        const paper = await prisma.paper.findFirst({
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

        const answersheet = await prisma.answerSheets.create({
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
    } catch (error) {
        console.error("Error adding answer sheet:", error);
        res.status(500).json({ message: "An error occurred while adding the answer sheet" });
    }
});


export default router