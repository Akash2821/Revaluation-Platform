import { selector } from 'recoil';
import {Username} from "../atoms/UserName.tsx";
export const UserFirstChar = selector({
    key : "UserFirstChar",
    get : ({get}) => {
        const userName = get(Username);
        return userName[0];
    }
})