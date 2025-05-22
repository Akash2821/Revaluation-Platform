import {useEffect, useState} from "react";
import axios from "axios";
import {useNavigate} from "react-router-dom";
import { useSetRecoilState} from "recoil";

import {USerType} from "../stores/atoms/UserType.tsx";
import {Username} from "../stores/atoms/UserName.tsx";
import {UserUserName} from "../stores/atoms/UserUserName.tsx";
enum User{
    student,
    teacher,
    admin,
}

interface WhoAmIResponse {
    msg: string;
    type: User;
    name : string;
    username : string;
}

function useVerify(n : User){
    const setUserType = useSetRecoilState(USerType);
    const setUserName = useSetRecoilState(Username);
    const setUserUserName = useSetRecoilState(UserUserName);
    const navigate = useNavigate();
    const [done ,setDone] = useState(false);
    useEffect(()=> {
        const token = localStorage.getItem("easyRevalToken");
        if(token === null){
            setDone(true);
            navigate("/signin");
            return
        }
        axios.get<WhoAmIResponse>("http://localhost:3000/whoami", {
            headers : {
                Authorization: token
            }
        })
            .then((response:any) => {
                console.log(response)
                if(response.data.msg === "success"){
                    if(response.data.type !== n){
                        localStorage.removeItem("easyRevalToken");
                        navigate("/signin");
                    }
                    else{
                        setUserType(response.data.type)
                        setUserName(response.data.name);
                        setUserUserName(response.data.username);
                    }
                    setDone(true);
                }
            })
            .catch((error:any) => {
                console.log(error);
                localStorage.removeItem("easyRevalToken");
                navigate("/signin");

            })
    },[])
    return done;
}

export default useVerify;