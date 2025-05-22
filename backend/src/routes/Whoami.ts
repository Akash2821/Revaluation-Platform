import { Router } from 'express';
import jwt, {JwtPayload} from "jsonwebtoken";
const router = Router();
const jwtSecret = process.env.JWT_SECRET || "yogiman";

router.get("/",(req,res)=>{
    const token = req.headers.authorization as string;
    try{
        //console.log(token)
        const jwtString = token.split(" ")[1];
        //console.log(jwtString);
        const decodedValue= jwt.verify(jwtString, jwtSecret) as JwtPayload;
        //console.log(decodedValue);
        res.status(200).json({
            msg : "success",
            name : decodedValue.name,
            username : decodedValue.username,
            type : decodedValue.type,
        })
    }
    catch(error :any){
        console.error('JWT verification failed:', error);
        res.status(401).json({
            msg: "Unauthorized",
            error: error.message,
        });
    }
})

export default router;
