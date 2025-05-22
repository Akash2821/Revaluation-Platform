import {Router} from 'express';
import zod from 'zod';
import {PrismaClient} from '@prisma/client';


const router = Router();
const prisma: PrismaClient= new PrismaClient({log:["query","info"]});
const RegisterInput = zod.object({
    organizationName  : zod.string(),
    organizationCode : zod.string(),
    adminName : zod.string(),
    adminUsername : zod.string(),
    adminPassword : zod.string()
})

router.post("/",async (req,res)=>{
    const organizationName : string = req.body.organizationName;
    const organizationCode : string = req.body.organizationCode;
    const adminName: string = req.body.adminName;
    const adminUsername : string = req.body.adminUsername;
    const adminPassword : string = req.body.adminPassword;
    const valid = RegisterInput.safeParse({organizationName, organizationCode, adminName,adminUsername , adminPassword});
    if(valid.success){
        console.log("input valid");
        console.log(organizationCode);
        const result = await prisma.organization.findUnique({
            where : {
                code : organizationCode
            }
        })
        console.log("user finding");
        if(result){
            res.status(401).json({
                msg : "code already being used, please use a different code"
            })
            return;
        }
        if(adminUsername.startsWith(organizationCode)){
            await prisma.organization.create({
                data : {
                    code: organizationCode,
                    organizationName : organizationName,
                    admin : {
                        create : {
                            name : adminName,
                            username : adminUsername,
                            password : adminPassword
                        }
                    }
                }
            })
            res.status(200).json({
                msg : "success"
            })
        }
        else{
            res.status(400).json({
                msg : "admin username should begin with organization code"
            })
        }
    }
    else{
        res.status(400).json({
            msg : "Invalid input"
        })
    }
})


export default router;