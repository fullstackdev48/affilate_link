import Link from "next/link";

import {
  homeItems,
  blogItems,
  pageItems,
  dashboardItems,
} from "../../data/mainMenuData";
import CategoriesMegaMenu from "./CategoriesMegaMenu";
import {
  isActiveParent,
  isActiveLink,
  isActiveParentChaild,
} from "../../utils/linkActiveChecker";
import { useRouter } from "next/router";
import { useSelector } from "react-redux";


const MainMenu = ({ style = "" }) => {
  const router = useRouter();
  const user = useSelector((state) => state.User.user);

  return (
    <nav className="menu js-navList">
      <ul className={`menu__nav ${style} -is-active`}>
        <li className={router.pathname === "/" ? "current" : ""}>
          <Link href="/">Home</Link>
        </li>
        {user._id && <li className={router.pathname === "/business/link" ? "current" : ""}>
          <Link href="/business/link">Affiliate</Link>
        </li>}
        {user.role === "admin" && <li className={router.pathname.slice(0, 5) === "/admin" ? "current" : ""}>
          <Link href="/admin/dashboard">Administrator</Link>
        </li>}

      </ul>
    </nav>
  );
};

export default MainMenu;
