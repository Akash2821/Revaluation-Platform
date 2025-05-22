import Navbar from "../components/Navbar.tsx";
import Hero from "../components/Hero.tsx";
import useRedirect from "../hooks/useRedirect.tsx";
import Footer from "../components/Footer.tsx";

function Landing() {
    const done = useRedirect()
    return (
        done?
        <div>
            <Navbar />
            <Hero />
            <Footer/>
        </div>
            :
            <div>
                Loading
            </div>
    )
}

export default Landing;