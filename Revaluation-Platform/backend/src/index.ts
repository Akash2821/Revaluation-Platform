import express from "express";
import cors from "cors";
import adminRouter from "./routes/Admin"
import studentRouter from "./routes/Student"
import teacherRouter from "./routes/Teacher"
import WhoamiRouter from "./routes/Whoami";
import registerRouter from "./routes/Register";
const app = express();
const port : number = 3000;
const jwtSecret = process.env.JWT_SECRET || "yogiman";


app.use(cors());
app.use(express.json({limit:"50mb"}));

app.use("/whoami",WhoamiRouter);
app.use("/admin",adminRouter);
app.use("/student",studentRouter);
app.use("/teacher",teacherRouter);
app.use("/register",registerRouter);


app.listen(port, () => {
    console.log(`Server started on port ${port}`);
})