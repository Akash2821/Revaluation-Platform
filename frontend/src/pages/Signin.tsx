import Input from "../components/Input";
import { useState} from "react";
import {useNavigate} from "react-router-dom";
import axios from "axios";
import useRedirect from "../hooks/useRedirect.tsx";
import {USerType} from "../stores/atoms/UserType.tsx";
import {useSetRecoilState} from "recoil";
import {Username} from "../stores/atoms/UserName.tsx";
import {UserUserName} from "../stores/atoms/UserUserName.tsx";
//import {Simulate} from "react-dom/test-utils";
//import error = Simulate.error;
enum User{
    student,
    teacher,
    admin
}



function Signin() {
    const done : boolean = useRedirect();
    const setUserType = useSetRecoilState(USerType);
    const setUserName = useSetRecoilState(Username);
    const setUserUserName = useSetRecoilState(UserUserName);

    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [type, setType] = useState(User.student);
    const [notification,setNotification] = useState("");
    const [view,setView] = useState(false);
    const navigate = useNavigate();
    //console.log(notification,view);
    const onClickHandler = (): void => {
        if (type === User.student) {
            axios.post("http://localhost:3000/student/login",{username:username,password:password})
                .then((response) => {
                    const data : any = response.data;
                    if(data.msg === "success"){
                        const token: string = "Bearer " + data.token;
                        localStorage.setItem("easyRevalToken", token);
                        setUserType(User.student);
                        setUserName(data.name);
                        setUserUserName(username);
                        navigate("/student")

                    }
                })
                .catch((error:any)=>{
                    if(error.response){
                        setNotification(error.response.data.msg);
                        setView(true);
                    }
                })


        }
        else if(type == User.teacher) {

            axios.post("http://localhost:3000/teacher/login",{username:username,password:password})
                .then((response) => {
                    const data:any = response.data;
                    if(data.msg === "success"){
                        const token: string = "Bearer " + data.token;
                        localStorage.setItem("easyRevalToken", token);
                        setUserType(User.teacher);
                        setUserName(data.name);
                        setUserUserName(username);
                        navigate("/teacher")
                    }
                })
                .catch((error:any)=>{
                    if(error.response){
                        setNotification(error.response.data.msg);
                        setView(true);
                    }
                })


        }
        else if(type == User.admin) {

            axios.post("http://localhost:3000/admin/login",{username:username,password:password})
                .then((response) => {
                    const data : any = response.data;
                    if(data.msg === "success"){
                        const token: string = "Bearer " + data.token;
                        localStorage.setItem("easyRevalToken", token);
                        setUserType(User.admin);
                        setUserName(data.name);
                        setUserUserName(username);
                        navigate("/admin");
                    }
                })
                .catch((error:any)=>{
                    if(error.response){
                        setNotification(error.response.data.msg);
                        setView(true);
                    }
                })


        }
    }
    return ( done?
        <div className={"w-full h-screen flex flex-col justify-center items-center"}>
            <div className={"fixed top-2 left-2"}>
                <button
                    className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={() => {
                        navigate("/")
                    }}
                >
                    Home
                </button>
            </div>
            <div className={"text-xl font-semibold text-red-400"}>
                {
                    view ? notification + " !!!" : " "
                }
            </div>
            <div className={"shadow-2xl p-8"}>
                <div className={"flex justify-center"}>
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100" width="250" height="70">
                        <circle cx="50" cy="50" r="40" fill="#1E90FF"/>
                        <text x="50" y="65"
                              fontFamily="Arial, sans-serif"
                              fontSize="40"
                              fill="white"
                              textAnchor="middle"
                              fontWeight="bold">ER
                        </text>

                        <text x="120" y="60"
                              fontFamily="Arial, sans-serif"
                              fontSize="36"
                              fill="#1E90FF"
                              fontWeight="bold">easyReval
                        </text>
                    </svg>
                </div>
                <h1 className={"text-2xl"}>Sign in to your account</h1>
                <Input label={"Username"} placeholder={"yogesh"} onChange={
                    (e) => {
                        setUsername(e.target.value);
                    }
                }></Input>
                <Input label={"password"} placeholder={"*******"} onChange={
                    (e) => {
                        setPassword(e.target.value);
                    }
                }></Input>
                <p>Choose the type of Login</p>
                <div className={"flex items-center justify-around py-2"}>
                    <input type={"radio"} id={"admin"} value={"admin"} checked={type === User.admin} onChange={() => {
                        setType(User.admin);
                    }}/>
                    <label htmlFor={"admin"} className={"px-2"}>Admin</label>

                    <input type={"radio"} id={"teacher"} value={"teacher"} checked={type === User.teacher}
                           onChange={() => {
                               setType(User.teacher);
                           }}/>
                    <label htmlFor={"teacher"} className={"px-2"}>Teacher</label>

                    <input type={"radio"} id={"student"} value={"student"} checked={type === User.student}
                           onChange={() => {
                               setType(User.student);
                           }}/>
                    <label htmlFor={"student"} className={"px-2"}>Student</label>
                </div>
                <button
                    className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={onClickHandler}
                >
                    Sign in
                </button>
            </div>
        </div>
            :
            <div>
                Loading
            </div>
    )
}

export default Signin;