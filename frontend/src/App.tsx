import {BrowserRouter,Routes,Route} from "react-router-dom";
import Landing from "./pages/Landing.tsx";
import Signin from "./pages/Signin.tsx";
import AdminDashboard from "./pages/AdminDashboard.tsx";
import TeacherDashboard from "./pages/TeacherDashboard.tsx";
import StudentDashboard from "./pages/StudentDashboard.tsx";
import {RecoilRoot} from "recoil";
import Register from "./pages/Register.tsx";

function App(){
    return (
        <RecoilRoot>
        <BrowserRouter>
            <Routes>
                <Route path={"/"} element={<Landing/>}></Route>
                <Route path={"/signin"} element={<Signin/>}></Route>
                <Route path={"/register"} element={<Register/>}></Route>
                <Route path={"/admin"} element={<AdminDashboard/>}></Route>
                <Route path={"/student"} element={<StudentDashboard/>}></Route>
                <Route path={"/teacher"} element={<TeacherDashboard/>}></Route>

            </Routes>
        </BrowserRouter>
        </RecoilRoot>
    )
}

export default App;