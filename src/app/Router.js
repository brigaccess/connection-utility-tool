import React from 'react';
import {Route, Switch, HashRouter} from 'react-router-dom';
import App from './containers/App';
import WelcomePage from './containers/WelcomePage';
import MenuPage from './containers/MenuPage';
import QuestionPage from './containers/QuestionPage';
import SearchPage from './containers/SearchPage';
import WrongSearchPage from './containers/WrongSearchPage';
import AppliancesPage from './containers/AppliancesPage';

const Router = () => (
    <HashRouter>
        <Switch>
            <Route exact path="/" component={App}/>
            <Route exact path="/welcome" component={WelcomePage}/>
            <Route exact path="/search" component={SearchPage}/>
            <Route exact path="/menu" component={MenuPage}/>
            <Route exact path="/question" component={QuestionPage}/>
            <Route exact path="/wrong" component={WrongSearchPage}/>
            <Route exact path="/available" component={AppliancesPage}/>
        </Switch>
    </HashRouter>
);

export default Router;

