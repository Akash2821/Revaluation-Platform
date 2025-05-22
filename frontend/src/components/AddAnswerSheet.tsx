import axios from "axios";
import { useState } from "react";

function AddAnswerSheet({ onClick }: { onClick: () => void }) {
    const [marksScored, setMarksScored] = useState<number | "">("");
    const [answerSheetFile, setAnswerSheetFile] = useState<File | null>(null);
    const [paperId, setPaperId] = useState<number | "">("");
    const [studentId, setStudentId] = useState<number | "">("");
    const [error, setError] = useState<string>("");

    const validateForm = (): boolean => {
        if (!marksScored || !answerSheetFile || !paperId || !studentId) {
            setError("All fields are required!");
            return false;
        }
        setError("");
        return true;
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

    const handleSubmit = async () => {
        if (!validateForm()) return;

        try {
            const base64File = await convertFileToBase64(answerSheetFile as File);

            const answerSheetData = {
                marksScored,
                answerSheet: base64File,
                paperId,
                studentId,
            };

            const response = await axios.post(
                "http://localhost:3000/admin/add-answersheet",
                answerSheetData,
                {
                    headers: {
                        "Authorization": localStorage.getItem("easyRevalToken") || "",
                        "Content-Type": "application/json",
                    },
                }
            );

            if (response.status === 201) {
                console.log("Answer sheet added successfully");
                setMarksScored("");
                setAnswerSheetFile(null);
                setPaperId("");
                setStudentId("");
            } else {
                console.error("Failed to add answer sheet");
                setError("Failed to add answer sheet. Please try again.");
            }
        } catch (error) {
            console.error("Error submitting answer sheet:", error);
            setError("An error occurred while submitting the answer sheet.");
        }
    };

    return (
        <div className="z-20 fixed top-0 left-0 backdrop-blur w-full h-screen flex flex-col items-center justify-center">
            <div className="fixed top-2 left-2" onClick={onClick}>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5"
                     stroke="currentColor" className="size-6">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </div>
            <div className="shadow-2xl p-8 bg-white">
                <div className="flex items-center justify-center">
                    <p className="text-xl font-semibold">Add Answer Sheet</p>
                </div>

                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        handleSubmit();
                    }}
                >
                    <div className="mb-4">
                        <label className="block text-sm font-semibold text-gray-700">Marks Scored</label>
                        <input
                            type="number"
                            value={marksScored}
                            onChange={(e) => setMarksScored(Number(e.target.value))}
                            placeholder="Enter Marks Scored"
                            className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                    </div>

                    <div className="mb-4">
                        <label className="block text-sm font-semibold text-gray-700">Answer Sheet (PDF)</label>
                        <input
                            type="file"
                            accept=".pdf"
                            onChange={(e) => setAnswerSheetFile(e.target.files ? e.target.files[0] : null)}
                            className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                    </div>

                    <div className="mb-4">
                        <label className="block text-sm font-semibold text-gray-700">Paper ID</label>
                        <input
                            type="number"
                            value={paperId}
                            onChange={(e) => setPaperId(Number(e.target.value))}
                            placeholder="Enter Paper ID"
                            className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                    </div>

                    <div className="mb-4">
                        <label className="block text-sm font-semibold text-gray-700">Student ID</label>
                        <input
                            type="number"
                            value={studentId}
                            onChange={(e) => setStudentId(Number(e.target.value))}
                            placeholder="Enter Student ID"
                            className="w-full mt-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                    </div>

                    {error && <p className="text-red-500 mb-4">{error}</p>}

                    <button
                        type="submit"
                        className="w-full bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    >
                        Add Answer Sheet
                    </button>
                </form>
            </div>
        </div>
    );
}

export default AddAnswerSheet;