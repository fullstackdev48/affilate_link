import { useEffect, useRef, useState } from "react";
import Pagination from "../../common/Pagination";
import ActionsButton from "./ActionsButton";
import { getOffers, deleteOffer, updateUser } from "../../../../services/affiliate/offer";
import Image from "next/image";
import Modal from "react-bootstrap/Modal";
import Dropdown from "./Dropdown";
import { ToastContainer, toast } from "react-toastify";
import OfferEditModal from "./OfferEditModal";
import MakeLinkModal from "./MakeLinkModal"

const AffiliateTable = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPage, setTotalPage] = useState(1)
  const [offers, setOffers] = useState([])
  const [modalShow, setModalShow] = useState(false)
  const [modalInfoShow, setModalInfoShow] = useState(false)
  const [selectedOfferId, setSelectedOfferId] = useState(999999999)
  const [isHovered, setIsHovered] = useState('');
  const [isAction, setIsAction] = useState(false);

  const [modalOfferShow, setModalOfferShow] = useState(false)

  
  const [selectedRole, setSeletedRole] = useState(null)
  const activeRef = useRef(null)
  const banRef = useRef(null)

  const handleTabClick = (index) => {
    setActiveTab(index);
  };

  const tabItems = [
    "Affiliate Links",
    // "Banned",
  ];

  const getOffersInPage = async (page) => {
    const res = await getOffers(page)
    if (res.success) {
      setTotalPage(res.totalPages)
      setOffers(res.offers)
    }
  }

  useEffect(() => {
    getOffersInPage()
  }, [])

  const handleMouseEnter = (id) => {
    setIsHovered(id);
  };

  const handleTagClick = (pageIndex) => {
    getOffersInPage(pageIndex)
    setCurrentPage(pageIndex)
  }

  const handleUpdate = (id) => {
    setSelectedOfferId(id)
    setModalShow(true)
  }

  const showOfferInfo = (id) => {
    
    !isAction && (
      setSelectedOfferId(id),
      setModalOfferShow(true)
    )

  }

  const handleDelete = async (id) => {
    const res = await deleteOffer(id)
    console.log(res)
    if (res.success) {
      toast.success(res.message);
      handleTagClick(currentPage)
    }
  }

  const handleClose = () => {
    setModalShow(false)
  }

  const handleInfoClose = () => {
    setModalInfoShow(false)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const isBanned = activeRef.current.checked ? false : true
    const role = selectedRole? selectedRole: users[selectedOfferId]?.role
    const body = {id: users[selectedOfferId]?._id, isBanned, role}
    const res = await updateUser(body)
    if (res.success) {
      toast.success(res.message);
      handleTagClick(currentPage)
    }
    setModalShow(false)
  }

  const handleOptionChange = (option) => {
    setSeletedRole(option)
  }

  const addOffer = (id) => {
    setModalOfferShow(true)
  }

  const handleOfferClose = () => {
    setModalOfferShow(false)
  setSelectedOfferId(9999999)
  }

  return (
    <>
      <div className="tabs -underline-2 js-tabs">
        <div className="tabs__content pt-30 js-tabs-content">
          <div className="tabs__pane -tab-item-1 is-tab-el-active">
            <div className="overflow-scroll scroll-bar-1">
              {/* <div className="d-flex justify-content-between">
                <div></div>
                <button
                  className="button h-50 px-24 -dark-1 bg-blue-1 text-white mb-10"
                  onClick={addOffer}
                >
                  <div className="icon-plus mr-15" /> Add 
                </button>
              </div> */}
              <table className="table-3 -border-bottom col-12">
                <thead className="bg-light-2">
                  <tr>
                    <th>ID</th>
                    <th>OFFER NAME</th>
                    <th>OFFER ID</th>
                    <th>AFFILIATE NAME</th>
                    <th>PAYOUT</th>
                    <th>CAP</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {
                    offers.map(({ _id, offerName, offerID, affiliateName, payout, cap }, index) =>
                      <tr key={_id} onClick={() => showOfferInfo(index)} onMouseEnter={() => handleMouseEnter(_id)} id={_id}  style={{ backgroundColor: isHovered === _id ? 'lightblue' : 'white' }} >
                        <td>{index + 1}</td>
                        <td>{offerName}</td>
                        <td>{offerID}</td>
                        <td>{affiliateName}</td>
                        <td>{payout}</td>
                        <td>{cap}</td>
                        <td onMouseEnter={() => setIsAction(true)} onMouseLeave={() => setIsAction(false)} > 
                          <ActionsButton onDelete={handleDelete} onUpdate={handleUpdate} id={_id} index={index}  />
                        </td>
                      </tr>
                    )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <Modal
        show={modalOfferShow}
        onHide={handleOfferClose}
        className="d-flex align-items-center justify-content-center"
        size='lg'
      >
        <Modal.Header
          closeButton
          style={{ borderBottom: "none" }}
        > <Modal.Title>Offer Info Edit</Modal.Title></Modal.Header>
        <Modal.Body>
          <OfferEditModal dataSource={offers[selectedOfferId]} closeModal={handleOfferClose} update={handleTagClick} current={currentPage} />
        </Modal.Body>

      </Modal>

      <Modal
        show={modalShow}
        onHide={handleClose}
        className="d-flex align-items-center justify-content-center mt-100"
        size='xl'
      >
        <Modal.Header
          closeButton
          style={{ borderBottom: "none" }}
        > <Modal.Title>Make Link</Modal.Title></Modal.Header>
        <Modal.Body>
          <MakeLinkModal dataSource={offers[selectedOfferId]} closeModal={handleClose} update={handleTagClick} current={currentPage} />
        </Modal.Body>
      </Modal>

      <Pagination currentPage={currentPage} handleTagClick={handleTagClick} totalPage={totalPage} />
      <ToastContainer />
    </>
  );
};



export default AffiliateTable;

