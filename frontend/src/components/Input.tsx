import React from "react";

interface InputProps {
    label: string;
    placeholder: string;
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

function Input({ label, onChange, placeholder }: InputProps) {
    return (
        <div className="mb-4 sm:min-w-[350px]">
            <p className="mb-2 text-gray-700 font-semibold">{label}</p>
            <input
                type="text"
                onChange={onChange}
                required
                placeholder={placeholder}
                className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
        </div>
    );
}

export default Input;
