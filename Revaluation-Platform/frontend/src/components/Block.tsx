import React from "react";
// import {useNavigate} from "react-router-dom";
import { useState } from "react";

interface FeatureCardProps {
    svg: JSX.Element; // For SVG, we will pass JSX directly
    title: string;
    description: string;

}

const FeatureCard: React.FC<FeatureCardProps> = ({ svg, title, description }) => {
    const [isHovered, setIsHovered] = useState(false);
    //const navigate = useNavigate();
    return (
            <div
                className={`transition-all duration-300 ease-in-out transform p-6 rounded-lg border bg-white shadow-lg group-hover:scale-105 group-hover:shadow-2xl ${isHovered ? 'scale-105 shadow-2xl' : ''}`}
                onMouseEnter={() => setIsHovered(true)}
                onMouseLeave={() => setIsHovered(false)}

            >

                <div className="flex justify-center items-center">
                    <div className="w-16 h-16 flex items-center justify-center p-3 bg-blue-100 rounded-full">
                        {svg} {/* This will render the SVG icon */}
                    </div>
                </div>
                <h3 className="text-xl font-semibold mt-4 text-center">{title}</h3>
                <p className="text-gray-500 text-center mt-2">{description}</p>
            </div>
    );
};

export default FeatureCard;
