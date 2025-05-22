import {Router} from 'express';
import zod from "zod";
import {PrismaClient} from "@prisma/client";
import jwt from "jsonwebtoken";
const router : Router = Router();
const prisma: PrismaClient= new PrismaClient({log:["query","info"]});
const jwtSecret = process.env.JWT_SECRET || "yogiman";
import authorize from "../middlewares/authorize";

const studentInput = zod.object({
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
    const valid = studentInput.safeParse({username, password});
    if(valid.success){

        const result = await prisma.student.findUnique({
            where:{
                username:username
            }
        });

        if(result){
            if(result.password === password){
                const token = jwt.sign({username:username,type:User.student,name:result.name,organizationId:result.organizationId},jwtSecret);
                res.status(200).json({
                    msg : "success",
                    token : token,
                    type : User.student,
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

router.get("/results", authorize, async (req, res) => {
    const username = req.headers.username as string;

    try {
        const answerSheets = await prisma.answerSheets.findMany({
            where: {
                student: {
                    username: username
                }
            },
            include: {
                paper: {
                    include: {
                        subject: true
                    }
                }
            }
        });

        const results = answerSheets.map(answerSheet => ({
            subjectName: answerSheet.paper.subject.name,
            marksScored: answerSheet.marksScored
        }));

        res.status(200).json({
            msg: "success",
            results
        });
    } catch (error) {
        console.error("Error fetching results:", error);
        res.status(500).json({ msg: "An error occurred while fetching the results" });
    }
});

router.post("/apply-reval", authorize, async (req, res) => {
    const username = req.headers.username as string;
    const { subjectCode } = req.body;

    if (!subjectCode) {
        res.status(400).json({ msg: "Subject code is required" });
        return;
    }

    try {
        const student = await prisma.student.findUnique({
            where: {
                username: username
            }
        });

        if (!student) {
            res.status(404).json({ msg: "Student not found" });
            return;
        }

        const updatedAnswerSheets = await prisma.answerSheets.updateMany({
            where: {
                studentId: student.id,
                paper: {
                    subject: {
                        subjectCode: subjectCode
                    }
                }
            },
            data: {
                applyReval: true
            }
        });

        if (updatedAnswerSheets.count === 0) {
            res.status(404).json({ msg: "No answer sheets found for the given subject code" });
            return;
        }

        res.status(200).json({
            msg: "Revaluation applied successfully",
        });
    } catch (error) {
        console.error("Error applying revaluation:", error);
        res.status(500).json({ msg: "An error occurred while applying for revaluation" });
    }
});


router.get("/answer-sheets",authorize,async (req,res)=>{
    const username = req.headers.username as string;
    const answerSheets = await prisma.answerSheets.findMany({
        where : {
            student:{
                username: username
            }
        }
    })
    res.status(200).json({
        msg : "success",
        answerSheets : answerSheets
    })
})

export default router