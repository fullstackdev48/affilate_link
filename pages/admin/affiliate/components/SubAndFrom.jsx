import React, { useState, useRef, useEffect } from "react";
import { addSub, addName, editSubject, editFromName } from "../../../../services/affiliate/offer";
import { ToastContainer, toast } from "react-toastify";

const SubAndFrom = (props) => {
  const offer = props.dataSource
  const [subjectLines, setSubjectLines] = useState(props.dataSource.subjectLines)
  const [fromNames, setFromNames] = useState(props.dataSource.fromNames)

  const editSub = (index) => {
    let newItems = subjectLines?.split(',')
    newItems[index] = newItems[index].slice(2)
    setSubjectLines(newItems.join(','))
  };

  const editName = (index) => {
    let newItems = fromNames?.split(',')
    newItems[index] = newItems[index].slice(2)
    setFromNames(newItems.join(','))
  };

  const inputSub = (e, index) => {
    let newItems = subjectLines?.split(',')
    newItems[index] = e.target.value
    setSubjectLines(newItems.join(','))
  };

  const inputName = (e, index) => {
    let newItems = fromNames?.split(',')
    newItems[index] = e.target.value
    setFromNames(newItems.join(','))
  };

  const submitSubs = async (e, index) => {
    e.preventDefault()

    let newItems = subjectLines.split(',')
    newItems[index] = '  ' + newItems[index]
    setSubjectLines(newItems.filter(v => v !== '').join(','))

    const formData = {
      id: offer._id,
      subjectLines: newItems.filter(v => v !== '').join(',')
    }

    if (offer) {
      const res = await editSubject({ formData })
      if (res.success) {
        toast.success(res.message);
        props.update(props.current)
      }
    }
  };

  const submitNames = async (e, index) => {
    e.preventDefault()

    let newItems = fromNames.split(',')
    newItems[index] = '  ' + newItems[index]
    setFromNames(newItems.filter(v => v !== '').join(','))

    const formData = {
      id: offer._id,
      fromNames: newItems.filter(v => v !== '').join(',')
    }

    if (offer) {
      const res = await editFromName({ formData })
      if (res.success) {
        toast.success(res.message);
        props.update(props.current)
      }
    }
  };

  const addSubject = async (e) => {
    e.preventDefault()

    setSubjectLines(subjectLines + ",  " +  e.target.value)

    const formData = {
      id: offer._id,
      subjectLine: e.target.value
    }

    if (offer) {
      const res = await addSub({ formData })
      if (res.success) {
        toast.success(res.message);
        props.update(props.current)
      }
    }
  };

  const addFromName = async (e) => {
    e.preventDefault()

    setFromNames(fromNames + ",  " +  e.target.value)

    const formData = {
      id: offer._id,
      fromName: e.target.value
    }

    if (offer) {
      const res = await addName({ formData })
      if (res.success) {
        toast.success(res.message);
        props.update(props.current)
      }
    }
  };

  return (
    <div className="col-12 text-center mt-10">

      <form>
        <div className="row y-gap-30">
          <div className="col-md-6">
            <div className="form-input">
              <input type="text" onBlur={addSubject} required />
              <label className="lh-1 text-16 text-light-1">Insert Subject</label>
            </div>
            <div className="">
              {subjectLines?.split(",").map((item, index) => (
                <div key={index} onDoubleClick={() => editSub(index)}>
                  {(item.slice(0, 2) !== '  ') ? (
                     <div className="form-input">
                      <input
                        type="text"
                        value={item}
                        onChange={(e) => inputSub(e, index)}
                        onBlur={(e) => submitSubs(e, index)}
                        autoFocus
                      />
                      <label className="lh-1 text-16 text-light-1">Edit Subject</label>
                      </div>
                  ) : (
                    <div>{item}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="col-md-6">
            <div className="form-input">
              <input type="text" onBlur={addFromName} required />
              <label className="lh-1 text-16 text-light-1">Insert From Name</label>
            </div>
            <div className="">
              {fromNames?.split(",").map((item, index) => (
                <div key={index} onDoubleClick={() => editName(index)}>
                  {(item.slice(0, 2) !== '  ') ? (
                     <div className="form-input">
                      <input
                        type="text"
                        value={item}
                        onChange={(e) => inputName(e, index)}
                        onBlur={(e) => submitNames(e, index)}
                        required
                      />
                      <label className="lh-1 text-16 text-light-1">Edit From Name</label>
                      </div>
                  ) : (
                    <div>{item}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </form >
      <ToastContainer />
    </div>
  );
};

export default SubAndFrom;
