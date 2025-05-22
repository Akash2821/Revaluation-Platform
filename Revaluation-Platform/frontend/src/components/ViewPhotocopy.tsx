import {useEffect, useState} from "react";
import axios from "axios";
import {Buffer} from "buffer";

function ViewPhotoCopy({ onClick }: { onClick: () => void }) {
    const [answerSheets, setAnswerSheets] = useState([]);
    const [view, setView] = useState(false);
    const [viewPaper,setViewPaper] = useState(false);
    const [paper,setPaper] = useState({
        answerPaper : ""
    });
    useEffect(() => {
        axios.get("http://localhost:3000/student/answer-sheets",{
            headers : {
                authorization : localStorage.getItem("easyRevalToken")
            }
        })
            .then((res:any)=>{
                if(res.status === 200){
                    setAnswerSheets(res.data.answerSheets);
                    setView(true);
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
            {view?
                viewPaper?
                    <div>
                        <embed src={`data:application/pdf;base64,${Buffer.from(paper.answerPaper).toString('base64')}`}
                               type="application/pdf" width="1000" height="600"/>
                        <button
                            className="mt-4 w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                            onClick={() => {
                                setViewPaper(false)
                            }}
                        >
                            Back
                        </button>
                    </div> :
                    <div className={"bg-white p-8 overflow-scroll"}>
                        <div className={"flex justify-center items-center text-2xl font-semibold py-6"}>
                            Your AnswerSheets
                        </div>
                        <div className={"border p-4"}>
                            {
                                answerSheets.map((answerSheet: any) => {
                                    return (<div className={"grid grid-cols-3 gap-2 capitalize text-2xl "} key={answerSheet.id}>
                            <div className={"flex justify-center items-center"}>
                                paper id : {answerSheet.id}
                            </div>
                            <div className={"flex justify-center items-center"}>
                                marks scored : {answerSheet.marksScored}
                            </div>
                            <button
                                className="mt-4 w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                                onClick={()=>{
                                    setPaper(answerSheet)
                                    setViewPaper(true)
                                }}
                            >
                                View
                            </button>
                        </div>)
                    })
                }
                </div>
            </div> :
                "Loading ...."
            }
        </div>
    )
}

export default ViewPhotoCopy;