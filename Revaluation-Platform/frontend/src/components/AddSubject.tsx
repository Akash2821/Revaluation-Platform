import Input from "./Input.tsx";
import {useState} from "react";
import axios from "axios";

function AddSubjects({onClick} : {onClick:()=>void}) {
    const [name, setName] = useState("");
    const [subjectCode, setSubjectCode] = useState("");
    const [notification,setNotification] = useState("");
    const [view,setView] = useState(false);
    const onClickHandler = () => {
        axios.post("http://localhost:3000/admin/add-subject", {
            name : name,
            subjectCode: subjectCode,
        },{
            headers : {
                authorization : localStorage.getItem("easyRevalToken"),

            }
        })
            .then((response)=>{
                const data:any = response.data;
                if(response.status === 200){
                    setNotification(data.msg);
                    setView(true);
                }
            })
            .catch((error:any)=>{
                if(error.response){
                    setNotification(error.response.data.msg);
                    setView(true);
                }
            })
    }
    return (
        <div
            className="z-20 fixed top-0 left-0 backdrop-blur w-full h-screen flex flex-col items-center justify-center">
            <div className={"fixed top-2 left-2"} onClick={onClick}>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5"
                     stroke="currentColor" className="size-6">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </div>
            <div className={"shadow-2xl p-8 bg-white"}>
                <div className={"text-xl font-semibold text-red-400"}>
                    {
                        view ? notification + " !!!" : " "
                    }
                </div>
                <div className={"flex items-center justify-center"}>
                    <p className={"text-xl font-semibold"}>Add Subject</p>
                </div>
                <Input label={"name"} placeholder={"Subject Name"} onChange={(e) => {
                    setName(e.target.value);
                }}/>
                <Input label={"code"} placeholder={"Subject Code"} onChange={(e) => {
                    setSubjectCode(e.target.value);
                }}/>
                <button
                    className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={onClickHandler}
                >
                    Add
                </button>
            </div>
        </div>
    )
}

export default AddSubjects;