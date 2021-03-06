import ChevronRightIcon from 'mdi-react/ChevronRightIcon'
import React from 'react'
import { Link } from 'react-router-dom'
import { Observable, Subscription } from 'rxjs'
import { catchError, map } from 'rxjs/operators'
import { gql, queryGraphQL } from '../../backend/graphql'
import * as GQL from '../../backend/graphqlschema'
import { buildSearchURLQuery } from '../../search'
import { asError, createAggregateError, ErrorLike, isErrorLike } from '../../util/errors'
import { RepoLink } from '../RepoLink'

interface Props {}

const LOADING: 'loading' = 'loading'

interface State {
    /** The repositories, loading, or an error. */
    repositoriesOrError: typeof LOADING | GQL.IRepositoryConnection | ErrorLike
}

/**
 * An explore section that shows a few repositories and a link to all.
 */
export class RepositoriesExploreSection extends React.PureComponent<Props, State> {
    private static QUERY_REPOSITORIES_ARG_FIRST = 4

    public state: State = { repositoriesOrError: LOADING }

    private subscriptions = new Subscription()

    public componentDidMount(): void {
        this.subscriptions.add(
            queryRepositories({ first: RepositoriesExploreSection.QUERY_REPOSITORIES_ARG_FIRST })
                .pipe(catchError(err => [asError(err)]))
                .subscribe(repositoriesOrError => this.setState({ repositoriesOrError }))
        )
    }

    public componentWillUnmount(): void {
        this.subscriptions.unsubscribe()
    }

    public render(): JSX.Element | null {
        const repositoriesOrError: (typeof LOADING | GQL.IRepository)[] | ErrorLike =
            this.state.repositoriesOrError === LOADING
                ? Array(RepositoriesExploreSection.QUERY_REPOSITORIES_ARG_FIRST).fill(LOADING)
                : isErrorLike(this.state.repositoriesOrError)
                    ? this.state.repositoriesOrError
                    : this.state.repositoriesOrError.nodes

        const itemClass = 'py-2 border-white'

        return (
            <div className="repositories-explore-section">
                <h2>
                    Repositories{' '}
                    {this.state.repositoriesOrError !== LOADING &&
                        !isErrorLike(this.state.repositoriesOrError) &&
                        typeof this.state.repositoriesOrError.totalCount === 'number' && (
                            <span className="text-muted">{this.state.repositoriesOrError.totalCount}</span>
                        )}
                </h2>
                {isErrorLike(repositoriesOrError) ? (
                    <div className="alert alert-danger">Error: {repositoriesOrError.message}</div>
                ) : repositoriesOrError.length === 0 ? (
                    <p>No repositories.</p>
                ) : (
                    <>
                        <div className="list-group list-group-flush">
                            {repositoriesOrError.map(
                                (repo /* or loading */, i) =>
                                    repo === LOADING ? (
                                        <div key={i} className={`${itemClass} list-group-item`}>
                                            <h3 className="text-muted mb-0">⋯</h3>&nbsp;
                                        </div>
                                    ) : (
                                        <Link
                                            key={i}
                                            className={`${itemClass} list-group-item list-group-item-action`}
                                            to={repo.url}
                                        >
                                            <h3 className="mb-0 text-truncate">
                                                <RepoLink to={null} repoPath={repo.name} />
                                            </h3>
                                            <span className="text-truncate">{repo.description || <>&nbsp;</>}</span>
                                        </Link>
                                    )
                            )}
                        </div>
                        <div className="text-right mt-3">
                            <Link to={`/search?${buildSearchURLQuery({ query: 'repo:' })}`}>
                                View all repositories<ChevronRightIcon className="icon-inline" />
                            </Link>
                        </div>
                    </>
                )}
            </div>
        )
    }
}

function queryRepositories(
    args: Pick<GQL.IRepositoriesOnQueryArguments, 'first'>
): Observable<GQL.IRepositoryConnection> {
    return queryGraphQL(
        gql`
            query ExploreRepositories($first: Int) {
                repositories(first: $first) {
                    nodes {
                        name
                        description
                        url
                    }
                    totalCount(precise: false)
                }
            }
        `,
        args
    ).pipe(
        map(({ data, errors }) => {
            if (!data || !data.repositories || (errors && errors.length > 0)) {
                throw createAggregateError(errors)
            }
            return data.repositories
        })
    )
}
