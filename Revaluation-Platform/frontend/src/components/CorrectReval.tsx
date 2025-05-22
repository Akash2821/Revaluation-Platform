import { useEffect, useState } from "react";
import axios from "axios";
import { Buffer } from "buffer";
import {Simulate} from "react-dom/test-utils";
import error = Simulate.error;

function CorrectReval({ onClick }: { onClick: () => void }) {
    const [subjects, setSubjects] = useState([]);
    const [done, setDone] = useState(false);
    const [viewPaper, setViewPaper] = useState(false);
    const [papers, setPapers] = useState([]);
    const [correct, setCorrect] = useState(false);
    const [paper, setPaper] = useState({
        answerPaper : "",
        id : ""
    });
    const [newMarks,setNewMarks] = useState("");

    useEffect(() => {
        axios.get("http://localhost:3000/teacher/subjects", {
            headers: {
                authorization: localStorage.getItem("easyRevalToken")
            }
        })
            .then((res: any) => {
                if (res.data.msg === "success") {
                    console.log(res.data);
                    setSubjects(res.data.subjects);
                    setDone(true);
                }
            })
            .catch((err) => {
                console.log(err);
                setDone(true);
            });
    }, []);

    const onclickHandler = (subjectCode: string) => {
        axios.post("http://localhost:3000/teacher/papers", {
            subjectCode: subjectCode,
        }, {
            headers: {
                authorization: localStorage.getItem("easyRevalToken")
            }
        })
            .then((response: any) => {
                if (response.status === 200) {
                    console.log("hello");
                    setPapers(response.data.answerSheets);
                    setViewPaper(true);
                }
            })
            .catch((error: any) => {
                console.log(error);
            });
    };
    const onSubmit = ()=>{
        axios.post("http://localhost:3000/teacher/update-marks", {
            answerSheetId : paper.id,
            newMarks : newMarks
        },{
            headers : {
                authorization : localStorage.getItem("easyRevalToken")
            }
        })
            .then((response:any) => {
                if(response.status === 200){
                    const newPapers = papers.filter((p:any)=>{
                        console.log(p.id,paper.id);
                        return p.id !== paper.id
                    })
                    setPapers(newPapers);
                    setCorrect(false);
                }
            })
            .catch((error)=>{
                console.log(error)
            })
    }

    return (
        <div className="z-20 fixed top-0 left-0 backdrop-blur w-full h-screen flex flex-col items-center justify-center">
            <div className="fixed top-2 left-2" onClick={onClick}>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5"
                     stroke="currentColor" className="size-6">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
            </div>
            {
                done ?
                    viewPaper ?
                        correct ?
                            <div>
                                <embed src={`data:application/pdf;base64,${Buffer.from(paper.answerPaper).toString('base64')}`}
                                       type="application/pdf" width="600" height="400" />
                                <div className="mt-4">
                                    <label htmlFor="updatedMarks" className="block text-sm font-medium text-gray-700">
                                        Updated Marks
                                    </label>
                                    <input
                                        type="number"
                                        onChange={(e)=>{setNewMarks(e.target.value)}}
                                        placeholder="Enter Max Marks"
                                        className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    />
                                    <button
                                        className="mt-4 w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                                        onClick={onSubmit}
                                    >
                                        Submit
                                    </button>
                                </div>
                            </div>
                            :
                            <div>
                                <div className={"text-2xl capitalize font-semibold flex justify-center pb-10"}>
                                    Papers for correction
                                </div>
                                {
                                    papers.map((paper: any) => {
                                        return <div key={paper.id}
                                                    className={"bg-white grid grid-cols-3 shadow-2xl"}>

                                            <div className={"px-10"}>
                                                paperId : {paper.paperId}
                                            </div>
                                            <div className={"px-10"}>
                                                marks Scored : {paper.marksScored}
                                            </div>
                                            <button
                                                className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                                                onClick={() => {
                                                    setPaper(paper);
                                                    console.log(paper);
                                                    setCorrect(true);
                                                }}
                                            >
                                                Correct
                                            </button>

                                        </div>
                                    })
                                }
                            </div> :
                        <div>
                            <div className={"text-2xl capitalize font-semibold flex justify-center pb-10"}>
                                Your subjects
                            </div>
                            {
                                subjects.map((subject: any) => {
                                    return <div key={subject.subjectCode} className={" bg-white shadow-2xl grid grid-cols-2 p-4 cursor-pointer"}
                                                onClick={() => {
                                                    onclickHandler(subject.subjectCode);
                                                }}
                                    >
                                        <div className={"pr-8 text-2xl capitalize font-semibold"}>
                                            subject name:
                                            {subject.name}
                                        </div>
                                        <div className={"pl-8 text-2xl capitalize font-semibold"}>
                                            subject code:
                                            {subject.subjectCode}
                                        </div>
                                    </div>
                                })
                            }
                        </div>
                    :
                    "Loading"
            }
        </div>
    );
}

export default CorrectReval;