import { useState} from "react";
import Input from "../components/Input";
import {useNavigate} from "react-router-dom";
import axios from "axios";

function Register() {
    const [notifications, setNotifications] = useState("");
    const [view,setView] = useState(false);
    const [name, setName] = useState("");
    const [userName, setUserName] = useState("");
    const [code, setCode] = useState("");
    const [rootAdmin,setRootAdmin] = useState("");
    const [rootPassword, setRootPassword] = useState("");
    const navigate = useNavigate();
    const onClickHandler = (): void => {
        axios.post("http://localhost:3000/register", {
            organizationName  : name,
            organizationCode : code,
            adminName : userName,
            adminUsername : rootAdmin,
            adminPassword : rootPassword,
        })
            .then((res:any) => {
                if(res.data.msg === "success"){
                    navigate("/signin");
                }
            })
            .catch((error:any)=>{
                if(error.response){
                    setNotifications(error.response.data.msg);
                    setView(true);
                }
            })
    }

    return (
        <div className={"w-full h-screen flex flex-col items-center justify-center"}>
            <div className={"fixed top-2 left-2"}>
                <button
                    className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={()=>{
                        navigate("/")
                    }}
                >
                    Home
                </button>
            </div>
            <div>
                {view ? notifications + " !!!" : ""}
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
                <h1 className={"text-2xl"}>Register Your Organization</h1>
                <Input label={'Organization Name'} placeholder={'PESU'} onChange={(e) => {
                    setName(e.target.value);
                }}></Input>
                <Input label={'Organization Code'} placeholder={'Unique 4 Characters'} onChange={(e) => {
                    setCode(e.target.value);
                }}></Input>
                <Input label={'Root Admin name'} placeholder={'Admin Name'}
                       onChange={(e) => {
                           setUserName(e.target.value);
                       }}></Input>
                <Input label={'Root Admin Username'} placeholder={'Should begin with Organization Code'}
                       onChange={(e) => {
                           setRootAdmin(e.target.value);
                       }}></Input>
                <Input label={'Root Admin Password'} placeholder={'Password'}
                       onChange={(e) => {
                           setRootPassword(e.target.value);
                       }}></Input>
                <button
                    className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={onClickHandler}
                >
                    Register
                </button>
                <div className={"text-sm pt-1 text-red-600"}>
                    * Note the code for each organization should be unique
                </div>
            </div>
        </div>
    )
}

export default Register;