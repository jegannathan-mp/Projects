// import { set } from 'mongoose';
import axios from 'axios';
import React, { useContext, useState } from 'react'
import { useNavigate} from 'react-router-dom';
import { ToastContainer, toast, Zoom } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css';
import { ContextValue } from '../App';
import { Button,Form, FormGroup,Label, Input } from 'reactstrap'
import '../styles/Forgot.css'
import backGround from '../assets/wall8.jpg'

const Forgot = () => {

    const navigate = useNavigate();
    const [inputEmail, setInputEmail] = useState()
    const { contId, setContId, contEmail, setContEmail } = useContext(ContextValue)

    let token = sessionStorage.getItem("token")
    // console.log(contEmail)

    const cancelButton = () => {
        navigate('/signin')
    }

    const searchButton = async (e) => {
        e.preventDefault();

        // debugger
        try {

            let response = await axios.get(`http://localhost:3100/bcryptget/${inputEmail}`,
            )
            setInputEmail(response.data.data)
            // console.log(response.data.statusCode)

            if (response.data.statusCode === 200) {
                sessionStorage.setItem('email', contEmail)


                toast.success('🦄 Email Found', {
                    position: "top-center",
                    autoClose: 3500,
                    hideProgressBar: false,
                    closeOnClick: true,
                    pauseOnHover: true,
                    draggable: true,
                    progress: undefined,
                    theme: "dark",
                    transition: Zoom,
                });
                setTimeout(() => navigate('/updatepass'), 1500);
                setContId(response.data.data._id)
            }

            if (response.data.statusCode == 404) {
                toast.error('🦄 Email Not Found', {
                    position: "top-center",
                    autoClose: 3500,
                    hideProgressBar: false,
                    closeOnClick: true,
                    pauseOnHover: true,
                    draggable: true,
                    progress: undefined,
                    theme: "dark",
                    transition: Zoom,
                });
            }

        } catch (error) {
            console.log(error);
        }
    }



    return (
        <>
            <div className='forgot_contain'>
            <ToastContainer />
                <img src={backGround} className='forgot_img' alt="" />
                <div className='forgot_divhead'>
                    <h2 className='forgot'>Find Your Account</h2>
                    
                    <Form className='forgot_form'>
                        <FormGroup className='forgot_1'>
                            <h4>
                                Please enter your email address to search for you account
                            </h4>
                        </FormGroup>
                        <FormGroup className='forgot_2'>
                            <Label htmlFor="email" className='forgot_label'>Email</Label>
                            <Input type="text" className='forgot_input' id='email' value={contEmail} onChange={(e) => { setInputEmail(e.target.value); setContEmail(e.target.value) }} placeholder='Email Address' />
                        </FormGroup>
                        <FormGroup className='forgot_3'>
                            <Button className='forgot_cancel' color='warning' onClick={cancelButton} >Cancel</Button>
                            <Button className='forgot_search' color='success' type='submit' onClick={searchButton} >Search</Button>
                        </FormGroup>
                    </Form>
                </div>
            </div>

        </>
    )
}

export default Forgot

