import { useState } from "react";
import Input from "./Input.tsx";
import axios from "axios";

// Paper type definition
type Paper = {
    maxMarks: string;
    questionPaperFile: File | null;
    subjectId: string;
};

function AddExam({ onClick }: { onClick: () => void }) {
    const [name, setName] = useState("");
    const [startTime, setStartTime] = useState("");
    const [endTime, setEndTime] = useState("");
    const [papers, setPapers] = useState<Paper[]>([
        { maxMarks: "", questionPaperFile: null, subjectId: "" }
    ]);
    const [error, setError] = useState<string | null>(null);

    const handleAddPaper = () => {
        setPapers([...papers, { maxMarks: "", questionPaperFile: null, subjectId: "" }]);
    };

    const handlePaperChange = (index: number, field: keyof Paper, value: string) => {
        const updatedPapers = [...papers];
        updatedPapers[index][field] = value;
        setPapers(updatedPapers);
    };

    const handleFileChange = (index: number, file: File | null) => {
        const updatedPapers = [...papers];
        updatedPapers[index].questionPaperFile = file;
        setPapers(updatedPapers);
    };

    const validateForm = () => {
        if (!startTime || !endTime) {
            setError("Start time and end time are required.");
            return false;
        }

        if (new Date(startTime) >= new Date(endTime)) {
            setError("End time must be after start time.");
            return false;
        }

        for (let i = 0; i < papers.length; i++) {
            const paper = papers[i];
            if (!paper.maxMarks || !paper.subjectId) {
                setError(`Max marks and subject ID are required for Paper ${i + 1}`);
                return false;
            }
            if (isNaN(Number(paper.maxMarks)) || Number(paper.maxMarks) <= 0) {
                setError(`Max marks for Paper ${i + 1} should be a valid positive number.`);
                return false;
            }
        }

        setError(null);
        return true;
    };

    const handleSubmit = async () => {
        if (!validateForm()) return;

        try {
            const papersWithBase64Files = await Promise.all(
                papers.map(async (paper) => {
                    let base64File = null;
                    if (paper.questionPaperFile) {
                        base64File = await convertFileToBase64(paper.questionPaperFile);
                    }

                    return {
                        ...paper,
                        questionPaper: base64File,
                    };
                })
            );

            const examData = {
                name,
                startTime,
                endTime,
                papers: papersWithBase64Files,
            };

            const response = await axios.post(
                "http://localhost:3000/admin/add-exam",
                examData,
                {
                    headers: {
                        "Authorization": localStorage.getItem("easyRevalToken") || "",
                        "Content-Type": "application/json",
                    },
                }
            );

            if (response.status === 201) {
                console.log("Exam added successfully");
                setName("");
                setStartTime("");
                setEndTime("");
                setPapers([{ maxMarks: "", questionPaperFile: null, subjectId: "" }]);
            } else {
                console.error("Failed to add exam");
                setError("Failed to add exam. Please try again.");
            }
        } catch (error) {
            console.error("Error submitting exam:", error);
            setError("An error occurred while submitting the exam.");
        }
    };

    const convertFileToBase64 = (file: File): Promise<string> => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onloadend = () => {
                const base64String = (reader.result as string).split(",")[1];
                resolve(base64String);
            };
            reader.onerror = (error) => reject(error);
            reader.readAsDataURL(file);
        });
    };

    return (
        <div className="z-20 fixed top-0 left-0 backdrop-blur w-full h-screen flex flex-col items-center justify-center">
            <div className="fixed top-2 left-2" onClick={onClick}>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="size-6">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </div>
            <div className="shadow-2xl p-8 bg-white max-h-screen overflow-scroll">
                <div className="flex items-center justify-center">
                    <p className="text-xl font-semibold">Add Exam</p>
                </div>

                {error && <div className="mb-4 text-red-500">{error}</div>}
                <Input label={"name"} placeholder={"Exam Name"} onChange={(e) => setName(e.target.value)}/>
                <div className="mb-4">
                    <label className="block text-sm font-semibold text-gray-700">Start Time</label>
                    <input
                        type="datetime-local"
                        value={startTime}
                        onChange={(e) => setStartTime(e.target.value)}
                        className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>
                <div className="mb-4">
                    <label className="block text-sm font-semibold text-gray-700">End Time</label>
                    <input
                        type="datetime-local"
                        value={endTime}
                        onChange={(e) => setEndTime(e.target.value)}
                        className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>

                <div className="mt-4">
                    <p className="text-lg font-semibold">Papers</p>
                    {papers.map((paper, index) => (
                        <div key={index} className="border p-4 mt-4">
                            <div className="mb-4">
                                <label className="block text-sm font-semibold text-gray-700">
                                    Max Marks (Paper {index + 1})
                                </label>
                                <input
                                    type="number"
                                    value={paper.maxMarks}
                                    onChange={(e) => handlePaperChange(index, "maxMarks", e.target.value)}
                                    placeholder="Enter Max Marks"
                                    className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>

                            <div className="mb-4">
                                <label className="block text-sm font-semibold text-gray-700">
                                    Question Paper (PDF)
                                </label>
                                <input
                                    type="file"
                                    accept=".pdf"
                                    onChange={(e) => handleFileChange(index, e.target.files?.[0] ?? null)}
                                    className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>

                            <div className="mb-4">
                                <label className="block text-sm font-semibold text-gray-700">
                                    Subject ID (Paper {index + 1})
                                </label>
                                <input
                                    type="text"
                                    value={paper.subjectId}
                                    onChange={(e) => handlePaperChange(index, "subjectId", e.target.value)}
                                    placeholder="Enter Subject ID"
                                    className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                        </div>
                    ))}
                    <button onClick={handleAddPaper} className="mt-4 px-4 py-2 bg-blue-500 text-white rounded-md">
                        Add Another Paper
                    </button>
                </div>

                <button onClick={handleSubmit} className="mt-6 px-4 py-2 bg-green-500 text-white rounded-md">
                    Submit
                </button>
            </div>
        </div>
    );
}

export default AddExam;