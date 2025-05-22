import {useRecoilValue} from "recoil";
import {UserFirstChar} from "../stores/selectors/UserFirstChar.tsx";
import {Username} from "../stores/atoms/UserName.tsx";
import {useNavigate} from "react-router-dom";
function UserNavbar() {
    const navigate = useNavigate();
    const firstChar = useRecoilValue(UserFirstChar);
    const username = useRecoilValue(Username);
    console.log(firstChar)
    return (
        <div className={"w-full px-8 py-4 flex items-center justify-between border border-gray-200"}>
            <div>
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100" width="250" height="70">
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
            <div className={"flex justify-center items-center"}>
                <div className="rounded-full bg-green-800 w-8 h-8 flex justify-center items-center cursor-pointer">
                    <p className="text-white font-bold text-2xl">{firstChar.toUpperCase()}</p>
                </div>
                <p className={"px-2 cursor-pointer"}>Hi, {username}</p>

                <button
                    className="bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={() => {
                        localStorage.removeItem("easyRevalToken");
                        navigate("/");
                    }}
                >
                    Log out
                </button>
            </div>

        </div>
    )
}

export default UserNavbar;