import useVerify from "../hooks/useVerify.tsx";
import UserNavbar from "../components/UserNavbar.tsx";
import Block from "../components/Block.tsx";
import Footer from "../components/Footer";

import books from "../assets/books-book-svgrepo-com.svg"
import student from "../assets/student-svgrepo-com.svg"
import teacher from "../assets/teacher-svgrepo-com.svg"
import admin from "../assets/hacker-svgrepo-com.svg"
import exam from "../assets/exam-result-svgrepo-com.svg"
// import question from "../assets/questions-help-svgrepo-com.svg"
import answer from "../assets/clipboard-document-result-svgrepo-com.svg"
import {useState} from "react";
import AddAdmin from "../components/AddAdmin.tsx";
import AddStudents from "../components/AddStudents.tsx";
import AddTeachers from "../components/AddTeachers.tsx";
import AddSubject from "../components/AddSubject.tsx";
import AddExam from "../components/AddExam.tsx";
import AddAnswerSheet from "../components/AddAnswerSheet.tsx";
import RemoveAdmin from "../components/RemoveAdmin.tsx";
import RemoveSubject from "../components/RemoveSubject.tsx";
import RemoveStudent from "../components/RemoveStudent.tsx";
import RemoveTeacher from "../components/RemoveTeacher.tsx";

function AdminDashboard(){
    const [addAdmins,setAddAdmins] = useState(false);
    const [addStudent,setAddStudent] = useState(false);
    const [addTeachers,setAddTeachers] = useState(false);
    const [addSubjects,setAddSubjects] = useState(false);
    const [addExams,setAddExams] = useState(false);
    // const [addQuestion,setAddQuestion] = useState(false);
    const [addAnsSheets,setAddAnsSheets] = useState(false);
    const [removeSubjects,setRemoveSubjects] = useState(false);
    const [removeAdmins,setRemoveAdmins] = useState(false);
    const [removeTeachers,setRemoveTeachers] = useState(false);
    const [removeStudent,setRemoveStudent] = useState(false);
    const done:boolean = useVerify(2)
    return (
        done ? (
            <div>{
                addAdmins?
                <AddAdmin onClick={()=>{
                    setAddAdmins(false);
                }}/>:
                    ""
            }
                {
                    addStudent?
                        <AddStudents onClick={()=>{
                            setAddStudent(false);
                        }}/>:
                        ""
                }
                {
                    addTeachers?
                        <AddTeachers onClick={()=>{
                            setAddTeachers(false);
                        }}/>:
                        ""
                }
                {
                    addSubjects?
                    <AddSubject onClick={()=>{
                        setAddSubjects(false);
                    }}/>:
                        ""
                }
                {
                    addExams?
                        <AddExam onClick={()=>{
                            setAddExams(false);
                        }}/>:
                    ""
                }
                {
                    addAnsSheets?
                        <AddAnswerSheet onClick={()=>{
                            setAddAnsSheets(false);
                        }}/>:
                        ""
                }
                {
                    removeAdmins?
                        <RemoveAdmin onClick={()=>{
                            setRemoveAdmins(false);
                        }}/>:
                        ""
                }
                {
                    removeSubjects?
                        <RemoveSubject onClick={()=>{
                            setRemoveSubjects(false);
                        }}/>:
                        ""
                }
                {
                    removeStudent?
                        <RemoveStudent onClick={()=>{
                            setRemoveStudent(false);
                        }}/>:
                        ""
                }
                {
                    removeTeachers?
                        <RemoveTeacher onClick={()=>{
                            setRemoveTeachers(false);
                        }}/>:
                        ""
                }
                <UserNavbar />
                <div className={"py-4 flex items-center justify-center"}>
                    <p className={"text-2xl font-semibold"}>Administration Dashboard</p>
                </div>
                <div className={"grid grid-cols-12 gap-4 px-4 py-8"}>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setAddAdmins(true);
                    }}>
                        <Block title={"Add Admins"} svg={<div>
                            <img src={admin} alt={"Admins"}/>
                        </div>}
                               description={"Add admins from your organization"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setAddStudent(true);
                    }}>
                        <Block title={"Add Students"} svg={<div>
                            <img src={student} alt={"Students"}/>
                        </div>}
                               description={"Add students from your organization"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setAddTeachers(true);
                    }}>
                        <Block title={"Add Teachers"} svg={<div>
                            <img src={teacher} alt={"Teachers"}/>
                        </div>}
                               description={"Add teachers from your organization"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setAddSubjects(true);
                    }}>
                        <Block title={"Add Subjects"} svg={<div>
                            <img src={books} alt={"Subjects"}/>
                        </div>}
                               description={"Add your organization's subjects"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setAddExams(true);
                    }}>
                        <Block title={"Add Exams"} svg={<div>
                            <img src={exam} alt={"Exams"}/>
                        </div>}
                               description={"Add your organization's Exams"}/>
                    </div>
                    {/*<div className={"col-span-12 md:col-span-4 lg:col-span-3"}>*/}
                    {/*    <Block title={"Add Question Paper"} svg={<div>*/}
                    {/*        <img src={question} alt={"Question Paper"}/>*/}
                    {/*    </div>}*/}
                    {/*           description={"Add your organization's Question Paper"}/>*/}
                    {/*</div>*/}
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setAddAnsSheets(true);
                    }}>
                        <Block title={"Add Answer sheets"} svg={<div>
                            <img src={answer} alt={"Answer sheets"}/>
                        </div>}
                               description={"Add your organization's Answer sheets"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setRemoveSubjects(true);
                    }}>
                        <Block title={"Remove Subjects"} svg={<div>
                            <img src={books} alt={"Subjects"}/>
                        </div>}
                               description={"Remove your organization's subjects"}/>
                    </div>


                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setRemoveAdmins(true);
                    }}>
                        <Block title={"Remove Admins"} svg={<div>
                            <img src={admin} alt={"Admins"}/>
                        </div>}
                               description={"Remove admins"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setRemoveStudent(true);
                    }}>
                        <Block title={"Remove Students"} svg={<div>
                            <img src={student} alt={"Students"}/>
                        </div>}
                               description={"Remove students"}/>
                    </div>
                    <div className={"col-span-12 md:col-span-4 lg:col-span-3"} onClick={()=>{
                        setRemoveTeachers(true);
                    }}>
                        <Block title={"Remove Teachers"} svg={<div>
                            <img src={teacher} alt={"Teachers"}/>
                        </div>}
                               description={"Remove teachers"}/>
                    </div>

                </div>
                <Footer/>

            </div>
        ) : (
            <div>
                Loading...
            </div>
        )
    );

}

export default AdminDashboard;