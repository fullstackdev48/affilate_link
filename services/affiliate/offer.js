import axios from "axios";

export const getOffers = async (page) => {
  console.log('getoffer===>')
  try {
    console.log("page",page)
    const params = {
      page
    }
    const res = await axios.get(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/getOffers`,
      {params}
    );
    const data = res.data;
    return data;
  } catch (error) {
    console.log("Error fetching data:", error);
  }
};

export const createOffer = async (formData) => {
  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/createOffer`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in creating Offer Information (service) => ", error);
  }
};

export const updateOffer = async (formData) => {
  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/updateOffer`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in updating Offer Information (service) => ", error);
  }
};

export const deleteOffer = async (_id) => {

  try {
    const res = await axios.delete(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/deleteOffer/${_id}`);
    const data = res.data;
    return data;
  } catch (error) {
    console.log("error in deleting Offer Information (service) => ", error);
  }
};

export const makeLink = async (formData) => {
  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/makeLink`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in making link (service) => ", error);
  }
};

export const addOfferLink = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addOfferLink`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding offer link (service) => ", error);
  }
};
export const addUnsubedLink = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addUnsubLink`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding offer link (service) => ", error);
  }
};
export const addPriLink = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addPrivacyLink`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding offer link (service) => ", error);
  }
};
export const addConditionLink = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addCondLink`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding offer link (service) => ", error);
  }
};
export const addTelLink = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addTelLink`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding telephone link (service) => ", error);
  }
};

export const addSub = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addSubject`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding subject (service) => ", error);
  }
};

export const addName = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/addName`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in adding Name (service) => ", error);
  }
};

export const editSubject = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/editSubject`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in editing Subject (service) => ", error);
  }
};

export const editFromName = async (formData) => {

  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/affiliate/editFromName`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      }
    );
    const data = res.json();
    return data;
  } catch (error) {
    console.log("error in editing Name (service) => ", error);
  }
};