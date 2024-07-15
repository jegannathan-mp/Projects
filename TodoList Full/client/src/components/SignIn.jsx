import axios from 'axios'
import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Link } from 'react-router-dom'
import { ToastContainer, toast, Zoom } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css';
import { Button, Form, FormGroup,  Label, Input } from 'reactstrap'
import '../styles/Signin.css'
import backGround from '../assets/wall5.jpg'

const SignIn = () => {

    const [name, setName] = useState('')
    const [pass, setPass] = useState('')
    const [email, setEmail] = useState('')

    const navigate = useNavigate()

    const signIn = async (e) => {
        e.preventDefault()
        try {
            // debugger
            const response = await axios.post('http://localhost:3100/mongodecrypt', {
                name: name,
                email: email,
                password: pass
            })
            // console.log(response)

            if (response.data.statusCode == 400) {
                alert('Email not found')
            }

            if (response.data.compare == true) {
                sessionStorage.setItem("email", email)
                sessionStorage.setItem("token", response.data.token)
                navigate('/todo')
            } else {
                toast.error('🦄 Password Wrong', {
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
            console.log('Fetching Error', error)
        }

    }
    return (
        <>
            <div className='signin_contain'>
                <ToastContainer />
                <img src={backGround} className='signin_img' alt="" />
                <div className='signin_divhead'>
                    <div className='signin_divhead1'>
                        <h1 className='signin'>Sign In</h1>
                        <Form onSubmit={signIn} className='signin_form' >
                            <FormGroup className='singnin_1'>
                                <Label htmlFor="name">Name : </Label>
                                <Input type="text" className='signin_input' id='name' value={name} onChange={(e) => setName(e.target.value)} />
                            </FormGroup>
                            <FormGroup className='singnin_2'>
                                <Label htmlFor="email">E-mail : </Label>
                                <Input type="email" id='email' className='signin_input' value={email} onChange={(e) => setEmail(e.target.value)} />
                            </FormGroup>
                            <FormGroup className='singnin_3'>
                                <Label htmlFor="password">Password : </Label>
                                <Input type="password" id='password' className='signin_input' value={pass} onChange={(e) => setPass(e.target.value)} />
                            </FormGroup>
                            <FormGroup className='singnin_4'>
                                <Button className='singin_btn' color='success' type="submit">Submit </Button>
                                <Label><Link to={'/forgot'}  className='signin_link' >Forgot Password...!</Link></Label>
                            </FormGroup>
                            <FormGroup className='singnin_5'>
                                <Label htmlFor="">Create a New account...!</Label>
                                <Link className='signin_link' to='/'>Sign Up</Link>
                            </FormGroup>
                        </Form>
                    </div>
                </div>
            </div>
        </>
    )
}

export default SignIn