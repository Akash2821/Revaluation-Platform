import {useEffect, useState} from "react";
import axios from "axios";
import {useNavigate} from "react-router-dom";
import {USerType} from "../stores/atoms/UserType.tsx";
import {useSetRecoilState} from "recoil";
import {Username} from "../stores/atoms/UserName.tsx";
import {UserUserName} from "../stores/atoms/UserUserName.tsx";

enum User{
    student,
    teacher,
    admin
}

interface WhoAmIResponse {
    msg: string;
    type: User;
    name : string;
    username : string;
}


function useRedirect(){
    const navigate = useNavigate();
    const [done,setDone] = useState(false);
    const setUserType = useSetRecoilState(USerType);
    const setUserName = useSetRecoilState(Username);
    const setUserUserName = useSetRecoilState(UserUserName);
    useEffect(() => {
        const token = localStorage.getItem("easyRevalToken");
        console.log(token)
        if(token === null){
            setDone(true)
            return;
        }
        axios.get<WhoAmIResponse>("http://localhost:3000/whoami", {
            headers : {
                Authorization: token
            }
        })
            .then((response:any) => {
                if(response.data.msg === "success"){
                    if(response.data.type === User.admin){
                        setUserType(User.admin)
                        setUserName(response.data.name);
                        setUserUserName(response.data.username);
                        console.log("/admin");
                        navigate("/admin");
                        setDone(true);
                    }
                    else if(response.data.type === User.teacher){
                        setUserType(User.teacher)
                        setUserName(response.data.name);
                        setUserUserName(response.data.username);
                        console.log("/teacher");
                        navigate("/teacher");
                        setDone(true);
                    }
                    else if(response.data.type === User.student){
                        setUserType(User.student)
                        setUserName(response.data.name);
                        setUserUserName(response.data.username);
                        console.log("/student");
                        navigate("/student");
                        setDone(true);
                    }
                }
                else{
                    console.log("wrong token")
                    setDone(true);
                }
            })
            .catch((error:any) => {
                console.log(error);
                setDone(true);
            })
    },[])
    return done;
}

export default useRedirect;