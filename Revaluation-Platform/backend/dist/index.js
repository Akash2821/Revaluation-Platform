"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const Admin_1 = __importDefault(require("./routes/Admin"));
const Student_1 = __importDefault(require("./routes/Student"));
const Teacher_1 = __importDefault(require("./routes/Teacher"));
const Whoami_1 = __importDefault(require("./routes/Whoami"));
const Register_1 = __importDefault(require("./routes/Register"));
const app = (0, express_1.default)();
const port = 3000;
const jwtSecret = process.env.JWT_SECRET || "yogiman";
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: "50mb" }));
app.use("/whoami", Whoami_1.default);
app.use("/admin", Admin_1.default);
app.use("/student", Student_1.default);
app.use("/teacher", Teacher_1.default);
app.use("/register", Register_1.default);
app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
