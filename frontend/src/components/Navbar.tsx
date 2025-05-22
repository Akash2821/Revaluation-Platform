import {useNavigate} from 'react-router-dom';
function Navbar(){
    const navigate = useNavigate();
    return (
        // fixed top-0 left-0 w-full  shadow-2xl
    <div className={"fixed top-0 left-0 w-full bg-blue-300  sm:flex sm:justify-between sm:items-center px-4 py-2 border-gray-500 border-b-2"}>
            <div className={""}>
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100"  width="250" height="70">
                    <circle cx="50" cy="50" r="40" fill="#1E90FF"/>
                    <text x="50" y="65"
                          fontFamily="Arial, sans-serif"
                          fontSize="40"
                          fill="white"
                          textAnchor="middle"
                          fontWeight="bold">ER
                    </text>

                    <text x="120" y="60"
                          fontFamily="Arial, sans-serif"
                          fontSize="36"
                          fill="#1E90FF"
                          fontWeight="bold">easyReval
                    </text>
                </svg>
            </div>
            <div className={"grid grid-cols-3 gap-4"}>
                <p className={"cursor-pointer flex justify-center items-center"}>Home</p>
                <p className={"cursor-pointer flex justify-center items-center"}>Contact Us</p>
                <button
                    className="bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={() => {
                        navigate("/signin");
                    }}
                >
                    Sign in
                </button>
            </div>
    </div>
    )
}

export default Navbar;