import image from "../assets/team.svg"
import team from "../assets/react.svg"
import {useNavigate} from "react-router-dom";
function Hero(){
    const navigate = useNavigate()
    return (
        <div className={"bg-blue-300 grid grid-cols-5 pt-36 sm:pt-28 lg:h-screen"}>
            <div className={"col-span-5 sm:col-span-3 p-8 lg:flex lg:items-center"}>
                <div>


                <h1 className="py-4 text-3xl sm:text-5xl font-bold bg-gradient-to-r from-blue-500 to-purple-600 bg-clip-text text-transparent">
                    Simplifying Paper Revaluation
                </h1>
                <p className={"py-6 tracking-wider"}>
                    <span className={"text-2xl font-semibold px-1"}>Schools , Colleges</span> <b> and </b><span
                    className={"text-2xl font-semibold px-2"}>Universities</span>
                    can easily register and upload their details on our platform, making the revaluation process quick
                    and hassle-free.
                </p>
                <button
                    className="bg-[#133E87] text-white font-semibold py-2 px-4 rounded hover:bg-[#0f2f66] transition duration-200"
                    onClick={() => {
                        navigate("/register");
                    }}
                >
                    Register Your Organization
                </button>
                <div className={"pt-20 text-gray-500  font-2xl"}>
                    <p>
                        From the most talented <span className={"text-blue-700 underline cursor-pointer"}>team</span> !
                    </p>
                    <div className={"flex"}>
                        <img className={"bg-black rounded-full "} src={team} alt={"people"}/>
                        <img className={"bg-black rounded-full "} src={team} alt={"people"}/>
                    </div>
                </div>
                </div>
            </div>
            <img className={"col-span-5 sm:col-span-2"} src={image} alt={"Landing"}/>
        </div>
    )
}

export default Hero;