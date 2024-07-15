import axios from 'axios'
import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Link } from 'react-router-dom'
import { ToastContainer, toast, Zoom } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css';
import { Button, Form, FormGroup, Label, Input } from 'reactstrap'
import '../styles/SignUp.css'
import backGround from '../assets/wall5.jpg'

const SignUp = () => {

    const navigate = useNavigate()

    const [name, setName] = useState('')
    const [email, setEmail] = useState('')
    const [pass, setPass] = useState('')
    const [confirmPass, setConfirmPass] = useState('')


    const saveData = async (e) => {
        e.preventDefault();
        // debugger
        if (pass !== confirmPass) {

            toast.error('🦄 Password Doesn \'t Match!', {
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
            return
        }

        try {

            let response = await axios.post('http://localhost:3100/mongoencrypt', { name: name, email: email, password: pass })

            if (response.data.statusCode === 200) {
                sessionStorage.setItem("email", email)
                sessionStorage.setItem("token", response.data.token)
            }

            navigate('/todo')
            // console.log(response)
        } catch (error) {
            console.log("Error Fectching", error)
        }
    }



    return (
        <>

            <div className='signup_contain'>
                <img src={backGround} className='signup_img' alt="" />
                <div className='signup_divhead'>
                    <div className='signup_divhead1'>
                        <h1 className='signup'>Sign Up</h1>
                        <Form onSubmit={saveData} className='signup_form'>
                            <FormGroup className='signup_1'>
                                <Label htmlFor="name">Name : </Label>
                                <Input className='signup_input' type="text" id='name' value={name} onChange={(e) => setName(e.target.value)} />
                            </FormGroup>
                            <FormGroup className='signup_2'>
                                <Label htmlFor="name">E-mail : </Label>
                                <Input className='signup_input' type="email" id='email' value={email} onChange={(e) => setEmail(e.target.value)} />
                            </FormGroup>
                            <FormGroup className='signup_3'>
                                <Label htmlFor="password">Password : </Label>
                                <Input className='signup_input' type="password" id='password' value={pass} onChange={(e) => setPass(e.target.value)} />
                            </FormGroup>
                            <FormGroup className='signup_4'>
                                <Label htmlFor="confirm password">Confirm Password : </Label>
                                <Input className='signup_input' type="password" id='confirm password' value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)} />
                            </FormGroup>
                            <ToastContainer />
                            <div className='signup_div'>
                                <FormGroup className='signup_6'>
                                    <Button type='submit' className='signup_btn' >Submit</Button>
                                </FormGroup>
                                <FormGroup className='signup_5'>
                                    <Label htmlFor="">Already have an account...!</Label>
                                    <Label><Link to='/signin' className='signup_link'>Sign In</Link></Label>
                                </FormGroup>
                            </div>
                        </Form>
                    </div>
                </div>
            </div>
        </>
    )
}

export default SignUp