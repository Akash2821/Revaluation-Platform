import {Router,Request,Response} from 'express';
import zod from "zod";
import {PrismaClient} from "@prisma/client";
import jwt from "jsonwebtoken";
import authorize from "../middlewares/authorize";
import Register from "./Register";
const router : Router = Router();
const prisma: PrismaClient= new PrismaClient({log:["query","info"]});
const jwtSecret = process.env.JWT_SECRET || "yogiman";

const TeacherInput = zod.object({
    username : zod.string(),
    password: zod.string()
})


enum User{
    student,
    teacher,
    admin
}

router.post("/login",async (req,res)=>{
    const username : string = req.body.username;
    const password: string = req.body.password;
    const valid = TeacherInput.safeParse({username, password});
    if(valid.success){

        const result = await prisma.teacher.findUnique({
            where:{
                username:username
            }
        });

        if(result){
            if(result.password === password){
                const token = jwt.sign({username:username,type:User.teacher,name:result.name,organizationId:result.organizationId},jwtSecret);
                res.status(200).json({
                    msg : "success",
                    token : token,
                    type : User.teacher,
                    name : result.name
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




router.post("/add-subject", authorize, async (req, res) => {
    const subjectCode = req.body.subjectCode  // Expecting teacherId and subjectCode in the request body
     const teacherUsername = req.headers.username as string;
    // Step 1: Validate the input
    if (!teacherUsername || !subjectCode) {
        res.status(400).json({
            msg: "Teacher ID and subject code are required"
        });
        return;
    }

    // Step 2: Check if the subject with the given subjectCode exists
    const subject = await prisma.subject.findUnique({
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
    const teacher = await prisma.teacher.findUnique({
        where: {
            username : teacherUsername
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
    await prisma.subject.update({
        where: {
            id: subject.id
        },
        data: {
            teachers: {
                connect: { id: teacher.id }  // Connect the teacher to the subject
            }
        }
    });

    res.status(200).json({
        msg: "Teacher successfully assigned to the subject"
    });
});

router.post("/remove-subject", authorize, async (req, res) => {
    const subjectCode = req.body.subjectCode;  // Expecting subjectCode in the request body
    const teacherUsername = req.headers.username as string;

    // Step 1: Validate the input
    if (!teacherUsername || !subjectCode) {
        res.status(400).json({
            msg: "Teacher username and subject code are required"
        });
        return;
    }

    // Step 2: Check if the subject with the given subjectCode exists
    const subject = await prisma.subject.findUnique({
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
    const teacher = await prisma.teacher.findUnique({
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
    await prisma.subject.update({
        where: {
            id: subject.id
        },
        data: {
            teachers: {
                disconnect: { id: teacher.id }  // Disconnect the teacher from the subject
            }
        }
    });

    res.status(200).json({
        msg: "Teacher successfully removed from the subject"
    });
    return;
});


router.get("/subjects",authorize,async (req:Request,res:Response)=>{
    const subjectList = prisma.
    teacher.findUnique({
        where: {
            username: req.headers.username as string
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
            msg : "success",
            subjects: teacher.subjects
        });
    }).catch(error => {
        res.status(500).json({
            msg: "Internal server error",
            error: error.message
        });
    });
})

router.post("/papers",authorize,async (req:Request,res:Response)=>{
    const subjectCode = req.body.subjectCode as string;
    const teacherUsername = req.headers.username as string;

    if (!teacherUsername || !subjectCode) {
        res.status(400).json({
            msg: "Teacher username and subject code are required"
        });
        return;
    }

    const teacher = await prisma.teacher.findUnique({
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

    const subject = await prisma.subject.findUnique({
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

    const answerSheets = await prisma.answerSheets.findMany({
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
})


router.post("/update-marks", authorize, async (req: Request, res: Response) => {
    try {
        const { answerSheetId, newMarks } = req.body;
        const organizationId: number  = req.headers.organizationId
            ? parseInt(req.headers.organizationId as string)
            : 0;

        if (!answerSheetId || !newMarks || isNaN(newMarks)) {
            res.status(400).json({ message: "Missing or invalid required fields" });
            return;
        }

        const answerSheet = await prisma.answerSheets.findFirst({
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

        const updatedAnswerSheet = await prisma.answerSheets.update({
            where: {
                id: parseInt(answerSheetId, 10)
            },
            data: {
                marksScored: parseInt(newMarks, 10),
                RevalDone: true
            }
        });

        res.status(200).json({ message: "Marks updated successfully", updatedAnswerSheet });
    } catch (error) {
        console.error("Error updating marks:", error);
        res.status(500).json({ message: "An error occurred while updating the marks" });
    }
});


export default router