import {useEffect, useState} from "react";
import axios from "axios";
import {Simulate} from "react-dom/test-utils";

function ViewResult({ onClick }: { onClick: () => void }) {
    const [result, setResult] = useState([]);
    const [loading, setLoading] = useState(true);
    useEffect(() => {
        axios.get("http://localhost:3000/student/results",{
            headers:{
                authorization : localStorage.getItem("easyRevalToken")
            }
        })
            .then((res:any)=>{
                if(res.status === 200){
                    setResult(res.data.results);
                    setLoading(false);
                }
            })
            .catch((error)=>{
                console.log(error);
            })

    },[])
    return (
        <div
            className="z-20 fixed top-0 left-0 backdrop-blur w-full h-screen flex flex-col items-center justify-center">
            <div className={"fixed top-2 left-2"} onClick={onClick}>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5"
                     stroke="currentColor" className="size-6">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </div>
            {loading?
                "Loading":
                <div className={"bg-white p-8"}>
                    <div className={"text-2xl font-semibold flex justify-center items-center py-6"}>
                        Result
                    </div>
                    <div className={"my-2 border p-4"}>
                        {result.map((res:any)=>{
                            return(
                            <div className={"grid grid-cols-2"}>
                                <div className={"text-xl capitalize flex justify-center"}>
                                    Subject name :
                                    {res.subjectName}
                                </div>
                                <div className={"text-xl capitalize  flex justify-center"}>
                                    Marks obtained :
                                    {res.marksScored}
                                </div>
                            </div>)
                        })}
                    </div>

                </div>
            }
        </div>
    )
}
export default ViewResult;