import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import '../styles/Input.css'
import { Button, Label, Input as Inputs } from 'reactstrap'


const Input = ({ getMethod }) => {
  const [inputval, setInputVal] = useState('')
  const navigate = useNavigate();

  let sessEmail = sessionStorage.getItem('email')
  let token = sessionStorage.getItem('token')
  // console.log(sessEmail)
  // console.log(inputval)


  let click = async () => {
    try {
      //  debugger
      let response = await axios.post('http://localhost:3100/todo',
        { Todo: inputval, email: sessEmail }, { headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` } }
      )
      // {headers:{'Content-Type':'application','Authorization':`Bearer ${token}`}}
      getMethod();
      setInputVal('')
    } catch (error) {
      console.log("Error fetching ", error)
    }
  }

  const logout = () => {
    sessionStorage.clear()
    navigate('/signin')
  }

  return (
    <>
      <div className='input_contain'>
          <div className='input_1'>
            <Label htmlFor="type" className='input_label'>Type here : </Label>
            <Inputs type="text" id='type' className='input_input' placeholder='Enter Your Todos...!' value={inputval} onChange={(e) => setInputVal(e.target.value)} />
          </div>
          <div className='input_2'> 
            <Button type='submit' className='input_submit' onClick={click}>Submit</Button>
            <Button onClick={logout} className='input_logout' >Logout</Button>
          </div>
      </div>

    </>
  )
}

export default Input